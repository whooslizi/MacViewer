//! The install identity and the machine details sent in registration
//! (MacRegistrationProfile.swift). Shares its file with the Go viewer.

use crate::messages::Registration;
use crate::wire::{hex, random_bytes, random_string, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use md5::{Digest, Md5};
use std::fs;
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

fn config_dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(d));
    }
    let home = std::env::var_os("HOME").ok_or("$HOME is not set")?;
    Ok(PathBuf::from(home).join(".config"))
}

/// The string value of `"key": "value"` in our own flat JSON file.
fn json_field(text: &str, key: &str) -> Option<String> {
    let rest = &text[text.find(&format!("\"{key}\""))? + key.len() + 2..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
    Some(rest[..rest.find('"')?].to_string())
}

pub fn load_registration() -> Result<Registration> {
    let dir = config_dir()?.join("macviewer-linux");
    fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    let path = dir.join("registration.json");
    let (identity, password) = match fs::read_to_string(&path) {
        Ok(text) => match (json_field(&text, "deviceIdentity"), json_field(&text, "password")) {
            (Some(i), Some(p)) if i.len() == 32 && i.bytes().all(|b| b.is_ascii_hexdigit())
                && p.len() == 8 && p.bytes().all(|b| b.is_ascii_digit()) => (i, p),
            _ => return Err(format!("{} is invalid; delete it to create a new identity", path.display()).into()),
        },
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let identity = hex(&Md5::digest(random_bytes(16))).to_uppercase();
            let password = random_string(8, b"0123456789");
            let text = format!("{{\n  \"deviceIdentity\": \"{identity}\",\n  \"password\": \"{password}\"\n}}\n");
            use std::io::Write;
            fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?.write_all(text.as_bytes())?;
            (identity, password)
        }
        Err(e) => return Err(e.into()),
    };

    let (local_address, mac_address) = primary_network()?;
    let host = fs::read_to_string("/proc/sys/kernel/hostname").map(|h| h.trim().to_string()).unwrap_or_else(|_| "linux".into());
    let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
    Ok(Registration {
        device_identity: identity, password, local_address, mac_address,
        computer_name_b64: STANDARD.encode(host),
        operating_system: kernel_version(),
        user_name: if user.is_ascii() { user } else { STANDARD.encode(user) },
    })
}

/// The IPv4 address used for outbound traffic, and the MAC of the default-route interface.
fn primary_network() -> Result<(String, String)> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect("8.8.8.8:80").map_err(|e| format!("no active IPv4 network connection: {e}"))?; // sends nothing; only picks a route
    let ip = s.local_addr()?.ip().to_string();
    let mac = |iface: &str| {
        let m = fs::read_to_string(format!("/sys/class/net/{iface}/address")).ok()?.trim().replace(':', "").to_uppercase();
        (m.len() == 12 && m != "000000000000").then_some(m)
    };
    // /proc/net/route: Iface Destination ...; destination 00000000 is the default route.
    let routes = fs::read_to_string("/proc/net/route").unwrap_or_default();
    let default_iface = routes.lines().skip(1).map(|l| l.split_whitespace().collect::<Vec<_>>())
        .find(|f| f.get(1) == Some(&"00000000")).map(|f| f[0].to_string());
    // A VPN interface has no MAC; use a real interface's, as MacViewer does.
    let mut ifaces: Vec<String> = fs::read_dir("/sys/class/net").map_err(|e| format!("cannot list network interfaces: {e}"))?
        .filter_map(|e| e.ok()?.file_name().into_string().ok()).filter(|n| n != "lo").collect();
    ifaces.sort();
    let found = default_iface.iter().chain(ifaces.iter()).find_map(|i| mac(i));
    Ok((ip, found.ok_or("no network interface with a hardware address")?))
}

/// Maps "6.8.0-45-generic" to the .NET Build|Major|MajorRevision|Minor|MinorRevision|Revision form.
fn kernel_version() -> String {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let v: Vec<u32> = release.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).take(3).map(|s| s.parse().unwrap_or(0)).collect();
    let at = |i: usize| v.get(i).copied().unwrap_or(0);
    format!("{}|{}|0|{}|0|0", at(2), at(0), at(1))
}

#[cfg(test)]
mod tests {
    #[test]
    fn json_field_reads_go_and_rust_files() {
        let text = "{\n  \"deviceIdentity\": \"ABC\",\n  \"password\":\"12345678\"\n}\n";
        assert_eq!(super::json_field(text, "deviceIdentity").as_deref(), Some("ABC"));
        assert_eq!(super::json_field(text, "password").as_deref(), Some("12345678"));
        assert_eq!(super::json_field(text, "missing"), None);
    }
}
