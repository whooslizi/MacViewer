//! A view-only relay session (UltraViewerRelaySession.swift): register, look up the
//! partner, log in through the relay and stream the screen.

use crate::messages::{login_text, lookup_text, parse_lookup_reply, parse_registration_reply, version_at_least, LoginContext, PeerInfo, Registration};
use crate::screen::{decode_screen_frame, decode_screen_init, Renderer, ScreenError, RESET_FRAME_NUMBER};
use crate::wire::{decode_envelope, decode_multipart, encode_frame, forward_envelope, http_preamble, random_string, system_envelope, CommandCipher, Envelope, Ipv4, Result, MAX_FRAME};
use base64::{engine::general_purpose::STANDARD, Engine};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::io::{self, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const COMMAND_HOST: &str = "functions3.ultraviewer.net";
pub const CLOSED: &str = "the remote computer disconnected";
const WRONG_PASSWORD: &str = "UltraViewer rejected the partner password";
const STEP_TIMEOUT: Duration = Duration::from_secs(20);
const HEARTBEAT: Duration = Duration::from_secs(10);

/// Everything a view-only session needs from the app. Callbacks run on the session thread.
pub struct Config {
    pub registration: Registration,
    /// This viewer's screen, reported in Login.
    pub screen_width: u32,
    pub screen_height: u32,
    pub display_name: String,
    pub on_status: Box<dyn FnMut(&str) + Send>,
    /// Top-down RGBA pixels, width, height. The buffer is reused; copy it.
    pub on_frame: Box<dyn FnMut(&[u8], usize, usize) + Send>,
    pub on_peer_changed: Box<dyn FnMut(&str, usize, usize) + Send>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Source {
    Command,
    Peer,
}

/// Everything the session thread waits on, in one channel.
pub enum Event {
    Frame(Source, Vec<u8>),
    Closed(Option<io::Error>),
    /// Sent by the app to end the session.
    Quit,
}

// --- FramedTCPTransport.swift ---

/// A connected byte stream; `sock` is the TCP socket underneath, kept for shutdown.
pub struct Stream {
    pub read: Box<dyn Read + Send>,
    pub write: Box<dyn Write + Send>,
    pub sock: TcpStream,
}

pub type Dial<'a> = &'a dyn Fn(&str, &str) -> io::Result<Stream>;

/// One connection carrying length-prefixed relay envelopes.
struct RelayConn {
    write: Box<dyn Write + Send>,
    sock: TcpStream,
}

impl RelayConn {
    fn open(s: Stream, host: &str, src: Source, tx: SyncSender<Event>) -> io::Result<Self> {
        let mut c = RelayConn { write: s.write, sock: s.sock };
        c.write.write_all(&http_preamble(host))?;
        c.write.flush()?;
        let read = s.read;
        thread::spawn(move || {
            let err = read_frames(read, src, &tx).err();
            let _ = tx.send(Event::Closed(err));
        });
        Ok(c)
    }

    fn send(&mut self, envelope: &[u8]) -> io::Result<()> {
        self.write.write_all(&encode_frame(envelope))?;
        self.write.flush()
    }
}

impl Drop for RelayConn {
    fn drop(&mut self) {
        let _ = self.sock.shutdown(Shutdown::Both); // unblocks the reader thread
    }
}

fn read_frames(read: Box<dyn Read + Send>, src: Source, tx: &SyncSender<Event>) -> io::Result<()> {
    let mut r = BufReader::with_capacity(64 * 1024, read);
    // Strip the HTTP response header (RelayHTTPPreambleDecoder).
    let mut header = vec![];
    while !header.ends_with(b"\r\n\r\n") {
        let mut b = [0u8];
        r.read_exact(&mut b)?;
        header.push(b[0]);
        if header.len() > 32768 {
            return Err(io::Error::other("relay HTTP header too large"));
        }
    }
    loop {
        let mut size = [0u8; 4];
        r.read_exact(&mut size)?;
        let n = u32::from_le_bytes(size) as usize;
        if n > MAX_FRAME {
            return Err(io::Error::other("relay frame too large"));
        }
        let mut frame = vec![0u8; n];
        r.read_exact(&mut frame)?;
        // A full channel blocks reads (TCP backpressure) instead of dropping frames.
        if tx.send(Event::Frame(src, frame)).is_err() {
            return Ok(());
        }
    }
}

// --- TLS: UltraViewer routes on SNI "ultraviewer" but its certificate names the real host. ---

#[derive(Debug)]
struct NamedVerifier {
    inner: Arc<WebPkiServerVerifier>,
    name: ServerName<'static>,
}

impl ServerCertVerifier for NamedVerifier {
    fn verify_server_cert(&self, end_entity: &CertificateDer, intermediates: &[CertificateDer], _sni: &ServerName,
                          ocsp: &[u8], now: UnixTime) -> std::result::Result<ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(end_entity, intermediates, &self.name, ocsp, now)
    }

    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer, d: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(m, c, d)
    }

    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer, d: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// rustls has no split stream: each half locks the connection only for in-memory work,
/// so a blocked socket read never holds up a write.
struct TlsHalf {
    conn: Arc<Mutex<ClientConnection>>,
    sock: TcpStream,
}

impl Read for TlsHalf {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut raw = vec![0u8; 16 * 1024];
        loop {
            match self.conn.lock().unwrap().reader().read(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                r => return r,
            }
            let n = self.sock.read(&mut raw)?;
            if n == 0 {
                return Ok(0);
            }
            let mut c = self.conn.lock().unwrap();
            let mut rest = &raw[..n];
            while !rest.is_empty() {
                c.read_tls(&mut rest)?;
                c.process_new_packets().map_err(io::Error::other)?;
            }
            while c.wants_write() {
                c.write_tls(&mut self.sock)?;
            }
        }
    }
}

impl Write for TlsHalf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut c = self.conn.lock().unwrap();
        c.writer().write_all(buf)?;
        while c.wants_write() {
            c.write_tls(&mut self.sock)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn dial_tls(addr: std::net::SocketAddr, cert_name: &str, timeout: Duration) -> io::Result<Stream> {
    let roots = Arc::new(RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() });
    let inner = WebPkiServerVerifier::builder(roots).build().map_err(io::Error::other)?;
    let name = ServerName::try_from(cert_name.to_string()).map_err(io::Error::other)?;
    let config = ClientConfig::builder().dangerous()
        .with_custom_certificate_verifier(Arc::new(NamedVerifier { inner, name }))
        .with_no_client_auth();
    let sni = ServerName::try_from("ultraviewer").expect("valid name");
    let mut conn = ClientConnection::new(Arc::new(config), sni).map_err(io::Error::other)?;
    let mut sock = TcpStream::connect_timeout(&addr, timeout)?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock)?;
    }
    sock.set_read_timeout(None)?;
    sock.set_write_timeout(Some(Duration::from_secs(10)))?;
    let conn = Arc::new(Mutex::new(conn));
    Ok(Stream {
        read: Box::new(TlsHalf { conn: conn.clone(), sock: sock.try_clone()? }),
        write: Box::new(TlsHalf { conn, sock: sock.try_clone()? }),
        sock,
    })
}

/// Dials a relay; an empty address means the command service, whose IPv4
/// addresses are tried in turn (RelayCommandConnection.swift).
pub fn dial(address: &str, cert_name: &str) -> io::Result<Stream> {
    if !address.is_empty() {
        let addr = (address, 443).to_socket_addrs()?.next().ok_or_else(|| io::Error::other("relay has no address"))?;
        return dial_tls(addr, cert_name, Duration::from_secs(10));
    }
    let mut last = io::Error::other("no IPv4 addresses");
    for addr in (COMMAND_HOST, 443).to_socket_addrs()?.filter(|a| a.is_ipv4()) {
        match dial_tls(addr, cert_name, Duration::from_secs(3)) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

// --- the session ---

#[derive(PartialEq)]
enum Phase {
    Registering,
    LookingUp,
    LoggingIn,
    Active,
}

struct Session {
    cfg: Config,
    partner_id: String,
    password: String,
    hash: String,
    correlation: i32,
    phase: Phase,
    cmd: RelayConn,
    peer: Option<RelayConn>,
    assigned_id: String,
    info: Option<PeerInfo>,
    target: Ipv4,
    target_port: u16,
    render: Option<Renderer>,
    accepted: bool,
    refreshes: u32,
    deadline: Option<Instant>,
    next_heartbeat: Option<Instant>,
    ticks: u32,
}

/// Connects to `partner_id` and streams its screen until `Event::Quit` arrives or the session fails.
/// `tx` is the sender half of `rx`, handed to the connection reader threads.
pub fn run(cfg: Config, partner_id: &str, password: &str, tx: SyncSender<Event>, rx: Receiver<Event>, dial: Dial) -> Result<()> {
    if partner_id.is_empty() || partner_id.len() > 64 || !partner_id.bytes().all(|b| b.is_ascii_digit()) || password.is_empty() {
        return Err("enter the Windows computer's UltraViewer ID and password".into());
    }
    let reg_text = cfg.registration.text().map_err(|e| format!("registration profile: {e}"))?;
    let mut cfg = cfg;
    (cfg.on_status)("Registering with UltraViewer…");
    let stream = dial("", COMMAND_HOST).map_err(|e| format!("the UltraViewer service did not respond: {e}"))?;
    let mut cmd = RelayConn::open(stream, COMMAND_HOST, Source::Command, tx.clone())?;
    cmd.send(&system_envelope(&CommandCipher::server().encrypt(reg_text.as_bytes()), true))?;
    let correlation = i32::from_str_radix(&random_string(9, b"0123456789"), 10).expect("digits") + 1;
    let mut s = Session {
        cfg, partner_id: partner_id.into(), password: password.into(),
        hash: random_string(16, b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
        correlation, phase: Phase::Registering, cmd, peer: None, assigned_id: String::new(), info: None,
        target: Ipv4::default(), target_port: 0, render: None, accepted: false, refreshes: 0,
        deadline: Some(Instant::now() + STEP_TIMEOUT), next_heartbeat: None, ticks: 0,
    };
    loop {
        let wake = [s.deadline, s.next_heartbeat].into_iter().flatten().min();
        let event = match wake {
            Some(t) => rx.recv_timeout(t.saturating_duration_since(Instant::now())),
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match event {
            Err(RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                if s.deadline.is_some_and(|d| d <= now) {
                    return Err("the Windows connection timed out".into());
                }
                if s.next_heartbeat.is_some_and(|h| h <= now) {
                    s.next_heartbeat = Some(now + HEARTBEAT);
                    s.heartbeat()?;
                }
            }
            Err(RecvTimeoutError::Disconnected) | Ok(Event::Quit) => {
                if s.phase == Phase::Active {
                    let _ = s.send_to_peer(b"19"); // RemoteControlCommands.endSession
                }
                return Ok(());
            }
            Ok(Event::Closed(err)) => {
                return Err(match err {
                    Some(e) if e.kind() != io::ErrorKind::UnexpectedEof => format!("{CLOSED}: {e}").into(),
                    _ => CLOSED.into(),
                });
            }
            Ok(Event::Frame(Source::Command, f)) => s.on_command(&f, dial, &tx)?,
            Ok(Event::Frame(Source::Peer, f)) => s.on_peer(&f)?,
        }
    }
}

fn valid_hostname(h: &str) -> bool {
    !h.is_empty() && h.len() <= 253 && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// Local UTC offset in minutes, for the lookup's time zone field.
fn tz_offset_minutes() -> i32 {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    // SAFETY: localtime_r only writes into tm.
    if unsafe { libc::localtime_r(&now, &mut tm) }.is_null() {
        return 0;
    }
    (tm.tm_gmtoff / 60) as i32
}

impl Session {
    fn arm_deadline(&mut self) {
        self.deadline = Some(Instant::now() + STEP_TIMEOUT);
    }

    fn on_command(&mut self, frame: &[u8], dial: Dial, tx: &SyncSender<Event>) -> Result<()> {
        let Envelope::System(payload) = decode_envelope(frame)? else { return Ok(()) };
        if self.phase == Phase::Registering && payload.starts_with(b"3:") {
            self.assigned_id = parse_registration_reply(payload)?;
            self.phase = Phase::LookingUp;
            (self.cfg.on_status)("Finding the Windows computer…");
            let text = lookup_text(&self.partner_id, &self.password, &self.assigned_id,
                                   &self.cfg.registration.password, self.correlation, tz_offset_minutes())?;
            self.arm_deadline();
            self.cmd.send(&system_envelope(&CommandCipher::server().encrypt(text.as_bytes()), true))?;
        } else if self.phase == Phase::LookingUp && payload.starts_with(b"8:") {
            let reply = parse_lookup_reply(payload)?;
            if reply.correlation != Some(self.correlation) {
                return Ok(());
            }
            if reply.status == 2 {
                return Err(WRONG_PASSWORD.into());
            }
            let Some(info) = reply.peer else {
                return Err(format!("UltraViewer declined the partner lookup (code {})", reply.status).into());
            };
            (self.target, self.target_port, self.phase) = (info.public_ip, info.target_port, Phase::LoggingIn);
            (self.cfg.on_status)("Connecting to the Windows computer…");
            let cert_name = if info.relay_hostname.is_empty() { COMMAND_HOST } else { &info.relay_hostname };
            if !valid_hostname(cert_name) {
                return Err("UltraViewer returned an invalid relay name".into());
            }
            let stream = dial(&info.relay_ip, cert_name).map_err(|e| format!("could not reach the UltraViewer relay: {e}"))?;
            self.peer = Some(RelayConn::open(stream, cert_name, Source::Peer, tx.clone())?);
            self.info = Some(info);
            (self.cfg.on_status)("Waiting for Windows to accept the session…");
            self.arm_deadline();
            self.login(0, false)?;
        }
        Ok(())
    }

    fn login(&mut self, control_mode: i32, clear: bool) -> Result<()> {
        let info = self.info.as_ref().expect("login after lookup");
        let text = login_text(&self.password, &random_string(8, b"0123456789"), &LoginContext {
            screen_width: self.cfg.screen_width, screen_height: self.cfg.screen_height,
            local_id: &self.assigned_id, display_name: &self.cfg.display_name,
            control_mode, clear_control_mode: clear,
            connection_hash: &self.hash, partner_secret_token: &info.secret_token,
        })?;
        self.send_to_peer(text.as_bytes())
    }

    fn send_to_peer(&mut self, payload: &[u8]) -> Result<()> {
        let env = forward_envelope(self.target, self.target_port, false, payload);
        Ok(self.peer.as_mut().expect("peer connected").send(&env)?)
    }

    fn heartbeat(&mut self) -> Result<()> {
        if self.phase != Phase::Active {
            return Ok(());
        }
        self.ticks += 1;
        self.peer.as_mut().expect("peer connected").send(&system_envelope(b"ping", false))?;
        self.send_to_peer(b"20")?;
        if self.ticks % 6 == 0 {
            // frmMain.tmPingServer: encrypted "2" every sixty seconds
            self.cmd.send(&system_envelope(&CommandCipher::server().encrypt(b"2"), true))?;
        }
        Ok(())
    }

    /// Renegotiates a complete screen after a bad update (refreshScreen in Swift).
    fn refresh(&mut self) -> Result<()> {
        self.refreshes += 1;
        self.render = None;
        self.phase = Phase::LoggingIn;
        (self.cfg.on_status)("Refreshing the Windows screen…");
        self.arm_deadline();
        self.login(-1, true)
    }

    fn relogin(&mut self, clear: bool) -> Result<()> {
        self.phase = Phase::LoggingIn;
        self.arm_deadline();
        self.login(-1, clear)
    }

    fn on_peer(&mut self, frame: &[u8]) -> Result<()> {
        let (ip, port, payload) = match decode_envelope(frame)? {
            Envelope::System(_) => return Ok(()), // relay "pong"
            Envelope::Forward { ip, port, payload } => (ip, port, payload),
        };
        let known = ip == self.target && port == self.target_port;
        let parts = match decode_multipart(payload) {
            Ok(p) if !p[0].is_empty() => p,
            _ if !known => return Ok(()),
            _ => return Err("the Windows computer returned incomplete screen information".into()),
        };
        let command = parts[0][0];
        let ours = parts.get(1).is_some_and(|p| *p == self.hash.as_bytes());
        if !known && !(command == 26 && ours) {
            return Ok(());
        }
        match command {
            0 if matches!(self.phase, Phase::LoggingIn | Phase::Active) => self.on_screen_init(&parts),
            1 if self.phase == Phase::Active && self.render.is_some() => self.on_screen_frame(&parts),
            23 if self.phase == Phase::Active => self.relogin(false),
            26 if ours => {
                (self.target, self.target_port, self.render) = (ip, port, None);
                if self.phase == Phase::Active {
                    return self.relogin(true);
                }
                Ok(())
            }
            27 | 41 | 54 => Err(CLOSED.into()),
            39 => Err("the Windows computer blocked this connection".into()),
            48 if self.phase == Phase::Active => match &mut self.render {
                Some(r) => r.set_tile_size(&parts),
                None => Ok(()),
            },
            _ => Ok(()),
        }
    }

    fn on_screen_init(&mut self, parts: &[&[u8]]) -> Result<()> {
        let si = decode_screen_init(parts)?;
        let changed = self.render.as_ref().is_none_or(|r| r.width != si.width || r.height != si.height);
        if changed && parts.get(13).is_some_and(|p| p.is_empty()) {
            return Err("the Windows computer returned incomplete screen information".into());
        }
        if !version_at_least(&si.version, [6, 0, 0]) {
            return Err(format!("this Windows UltraViewer version ({:?}) is not supported yet; 6.0.0 or later is required", si.version).into());
        }
        match &mut self.render {
            Some(r) if !changed => r.tile_size = si.tile_size,
            _ => {
                let last = self.render.as_ref().map_or(RESET_FRAME_NUMBER, |r| r.last);
                self.render = Some(Renderer::new(si.width, si.height, si.tile_size, last)?);
            }
        }
        self.phase = Phase::Active;
        self.deadline = None;
        self.next_heartbeat.get_or_insert(Instant::now() + HEARTBEAT);
        let info = self.info.as_ref().expect("screen after lookup");
        let name = match STANDARD.decode(&info.computer_name_b64) {
            Ok(b) if !b.is_empty() => String::from_utf8_lossy(&b).into_owned(),
            _ => self.partner_id.clone(),
        };
        (self.cfg.on_peer_changed)(&name, si.width, si.height);
        let status = if self.accepted {
            "Windows screen refreshed.".to_string()
        } else {
            format!("Connected to {name} (UltraViewer {}, {}x{}).", si.version, si.width, si.height)
        };
        (self.cfg.on_status)(&status);
        self.accepted = true;
        self.send_to_peer(b"17")
    }

    fn on_screen_frame(&mut self, parts: &[&[u8]]) -> Result<()> {
        let render = self.render.as_mut().expect("checked by caller");
        match decode_screen_frame(parts).and_then(|f| render.apply(&f)) {
            Ok(()) => {
                (self.cfg.on_frame)(&render.main, render.width, render.height);
                // Windows waits for this before sending the next update.
                self.send_to_peer(b"18")
            }
            Err(e) if e.is::<ScreenError>() => {
                self.send_to_peer(b"18")?;
                if self.refreshes >= 2 {
                    return Err(e);
                }
                (self.cfg.on_status)(&format!("Bad screen update ({e}); refreshing."));
                self.refresh()
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::tests::sample_registration;
    use crate::screen::tests::{long, parts, words, Fp};
    use crate::wire::encode_multipart;
    use std::io::BufRead;
    use std::net::TcpListener;
    use std::sync::mpsc::sync_channel;

    /// The server end of a plain localhost relay connection.
    struct FakeRelay {
        r: BufReader<TcpStream>,
        w: TcpStream,
    }

    impl FakeRelay {
        /// Accepts one client, consumes its HTTP preamble and answers it.
        fn accept(l: TcpListener) -> Self {
            let (c, _) = l.accept().unwrap();
            let mut f = FakeRelay { r: BufReader::new(c.try_clone().unwrap()), w: c };
            let mut line = String::new();
            while line != "\r\n" {
                line.clear();
                f.r.read_line(&mut line).unwrap();
            }
            f.w.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
            f
        }

        fn read(&mut self) -> Vec<u8> {
            let mut size = [0u8; 4];
            self.r.read_exact(&mut size).unwrap();
            let mut b = vec![0u8; u32::from_le_bytes(size) as usize];
            self.r.read_exact(&mut b).unwrap();
            b
        }

        fn write(&mut self, env: &[u8]) {
            self.w.write_all(&encode_frame(env)).unwrap();
        }

        /// Decrypts a [1, 0, ciphertext] request from the client.
        fn command(&mut self) -> String {
            let b = self.read();
            assert_eq!(&b[..2], [1, 0], "command envelope");
            String::from_utf8(CommandCipher::server().decrypt(&b[2..]).unwrap()).unwrap()
        }

        fn drain(&mut self) {
            let _ = io::copy(&mut self.r, &mut io::sink());
        }
    }

    fn plain(addr: std::net::SocketAddr) -> io::Result<Stream> {
        let sock = TcpStream::connect(addr)?;
        Ok(Stream { read: Box::new(sock.try_clone()?), write: Box::new(sock.try_clone()?), sock })
    }

    #[test]
    fn session_registers_looks_up_logs_in_and_streams_frames() {
        let peer_ip = Ipv4::parse("203.0.113.9").unwrap();
        let (cmd_l, peer_l) = (TcpListener::bind("127.0.0.1:0").unwrap(), TcpListener::bind("127.0.0.1:0").unwrap());
        let (cmd_addr, peer_addr) = (cmd_l.local_addr().unwrap(), peer_l.local_addr().unwrap());

        let cmd_server = thread::spawn(move || {
            let mut f = FakeRelay::accept(cmd_l);
            assert!(f.command().starts_with("3:"), "registration");
            f.write(&system_envelope(b"3:443:00111222333:203.0.113.7::0:p:-1:d:h:tok", false));
            let lookup = f.command();
            let l: Vec<&str> = lookup.split(':').collect();
            assert_eq!((l[0], l[1], l[6]), ("8", "123456789", "111222333"));
            f.write(&system_envelope(b"8:2:wrong-correlation", false)); // ignored: correlation mismatch
            let reply = format!("8:1:lan:x:203.0.113.9:1:2:3:V0lOUEM=:55100:x:198.51.100.2:0:3:relay.example:{}", l[9]);
            f.write(&system_envelope(reply.as_bytes(), false));
            f.drain();
        });
        let peer_server = thread::spawn(move || {
            let mut f = FakeRelay::accept(peer_l);
            let send = |f: &mut FakeRelay, parts: &[Vec<u8>]| {
                let refs: Vec<&[u8]> = parts.iter().map(|p| &p[..]).collect();
                f.write(&forward_envelope(peer_ip, 55100, false, &encode_multipart(&refs)));
            };
            let expect = |f: &mut FakeRelay, want: &str| {
                let b = f.read();
                match decode_envelope(&b).unwrap() {
                    Envelope::Forward { ip, port, payload } => {
                        assert!(ip == peer_ip && port == 55100 && payload.starts_with(want.as_bytes()), "peer got {payload:?}, want {want}")
                    }
                    e => panic!("peer got {e:?}"),
                }
            };
            expect(&mut f, "login:");
            // A stranger's forward is ignored.
            f.write(&forward_envelope(Ipv4([1, 2, 3, 4]), 9, false, &encode_multipart(&[&[27]])));
            send(&mut f, &[vec![0], long(2), long(1), vec![], vec![], vec![1], b"6.6.133".to_vec(), vec![1]]);
            expect(&mut f, "17");
            send(&mut f, &parts(&Fp { seq: RESET_FRAME_NUMBER + 1, rects: vec![0, 0, 2, 1], pixels: words(&[0x7c00, 0x001f]), ..Default::default() }));
            expect(&mut f, "18");
            send(&mut f, &[vec![27]]);
            f.drain();
        });

        let frames = Arc::new(Mutex::new(vec![]));
        let name = Arc::new(Mutex::new(String::new()));
        let (fr, nm) = (frames.clone(), name.clone());
        let cfg = Config {
            registration: sample_registration(), screen_width: 1920, screen_height: 1080, display_name: "LinuxViewer".into(),
            on_status: Box::new(|_| {}),
            on_frame: Box::new(move |px, _, _| fr.lock().unwrap().push(px.to_vec())),
            on_peer_changed: Box::new(move |n, _, _| *nm.lock().unwrap() = n.into()),
        };
        let dial = move |address: &str, cert_name: &str| {
            if address.is_empty() {
                return plain(cmd_addr);
            }
            assert_eq!((address, cert_name), ("198.51.100.2", "relay.example"));
            plain(peer_addr)
        };
        let (tx, rx) = sync_channel(64);
        let err = run(cfg, "123456789", "pw", tx, rx, &dial).unwrap_err();
        assert_eq!(err.to_string(), CLOSED);
        assert_eq!(*name.lock().unwrap(), "WINPC");
        assert_eq!(*frames.lock().unwrap(), [vec![255, 0, 0, 255, 0, 0, 255, 255]]);
        cmd_server.join().unwrap();
        peer_server.join().unwrap();
    }
}
