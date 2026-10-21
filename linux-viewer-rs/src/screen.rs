//! Screen path: ModernScreenMessage.swift (commands 0 and 1), ZstdScreenDecoder.swift
//! and ModernScreenRenderer.swift.

use crate::wire::{Error, Result};
use std::collections::HashMap;
use std::fmt;
use zstd_safe::{DCtx, DParameter, InBuffer, OutBuffer, ResetDirective};

/// UltraViewer's trained zstd dictionary, shared with the Swift package.
static SCREEN_DICTIONARY: &[u8] = include_bytes!("../../Sources/UltraViewerProtocol/Resources/8bit.dat");

/// Form1.ResetLastMsgNumber (0x80000001).
pub const RESET_FRAME_NUMBER: i32 = -2147483647;

const MAX_DIMENSION: i64 = 8192;
const MAX_PIXELS: i64 = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 16384;
const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024;
const MAX_AUX_TILES: usize = 1 << 20;
const MAX_ATLAS_SIDE: i64 = 65535;
const MAX_CACHE_ENTRIES: usize = 1000;

/// A bad screen update; the session answers it with a screen refresh.
#[derive(Debug)]
pub struct ScreenError(pub String);

impl fmt::Display for ScreenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ScreenError {}

fn screen_err(msg: impl Into<String>) -> Error {
    Box::new(ScreenError(msg.into()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

fn check_geometry(w: i64, h: i64) -> Result<()> {
    if w <= 0 || h <= 0 {
        return Err(screen_err(format!("invalid screen rectangle {w}x{h}")));
    }
    if w > MAX_DIMENSION || h > MAX_DIMENSION || w > MAX_PIXELS / h {
        return Err(screen_err(format!("screen rectangle {w}x{h} exceeds the supported size")));
    }
    Ok(())
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}

fn i32_at(b: &[u8], i: usize) -> i32 {
    i32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

fn int32_part(parts: &[&[u8]], i: usize) -> Result<i32> {
    match parts.get(i) {
        Some(p) if p.len() >= 4 => Ok(i32_at(p, 0)),
        _ => Err(screen_err(format!("malformed screen part {i}"))),
    }
}

// --- command 0 ---

#[derive(Debug)]
pub struct ScreenInit {
    pub width: usize,
    pub height: usize,
    pub tile_size: usize,
    pub version: String,
}

pub fn decode_screen_init(parts: &[&[u8]]) -> Result<ScreenInit> {
    if parts.len() < 3 || parts[0].first() != Some(&0) {
        return Err("malformed screen initialization".into());
    }
    let (w, h) = (int32_part(parts, 1)?, int32_part(parts, 2)?);
    check_geometry(w as i64, h as i64)?;
    let bad = |i: usize| screen_err(format!("malformed screen initialization part {i}"));
    for i in [5, 11] {
        if parts.get(i).is_some_and(|p| p.is_empty()) {
            return Err(bad(i));
        }
    }
    if parts.len() > 6 && parts.get(7).is_none_or(|p| p.is_empty()) {
        return Err(bad(7));
    }
    if parts.get(12).is_some_and(|p| p.len() < 2) {
        return Err(bad(12));
    }
    if parts.len() > 8 {
        int32_part(parts, 9)?;
        int32_part(parts, 10)?;
    }
    let mut tile_size = 16;
    if let Some(p) = parts.get(14) {
        match p.first() {
            Some(&t) if t != 0 => tile_size = t as usize,
            _ => return Err(bad(14)),
        }
    }
    let version = parts.get(6).map(|p| String::from_utf8_lossy(p).into_owned()).unwrap_or_default();
    Ok(ScreenInit { width: w as usize, height: h as usize, tile_size, version })
}

// --- command 1 ---

#[derive(Debug, PartialEq)]
pub struct CacheRef {
    pub x: i32,
    pub y: i32,
    pub hash: i32,
}

#[derive(Debug, PartialEq)]
pub struct CacheAdd {
    pub r: Region,
    pub hash: i32,
}

#[derive(Debug)]
pub struct ScrollOp {
    pub delta: i32,
    pub capture: Region,
    pub copy_back: Vec<Region>,
}

#[derive(Debug)]
pub struct ScreenFrame<'a> {
    pub number: i32,
    pub main: Vec<Region>,
    pub compressed: &'a [u8],
    pub copy_temp: Vec<Region>,
    pub scroll: Option<ScrollOp>,
    pub jpeg: &'a [u8],
    pub aux: Vec<Region>,
    pub refs: Vec<CacheRef>,
    pub adds: Vec<CacheAdd>,
}

pub fn decode_screen_frame<'a>(parts: &[&'a [u8]]) -> Result<ScreenFrame<'a>> {
    if parts.first().and_then(|p| p.first()) != Some(&1) {
        return Err(screen_err("unsupported screen update"));
    }
    if parts.len() <= 10 {
        return Err(screen_err("incomplete screen update"));
    }
    let main = regions(parts[1], 1, false)?;
    let copy_temp = regions(parts[5], 5, true)?;
    let aux = regions(parts[8], 8, true)?;
    let mut scroll = None;
    let p = parts[6];
    if !p.is_empty() {
        if p.len() < 10 || (p.len() - 10) % 8 != 0 || (p.len() - 10) / 8 > MAX_RECORDS {
            return Err(screen_err("malformed screen scroll"));
        }
        scroll = Some(ScrollOp {
            delta: u16_at(p, 0) as i16 as i32,
            capture: read_region(p, 2, true)?,
            copy_back: regions(&p[10..], 6, true)?,
        });
    }
    records(parts[9], 9, 8)?;
    let refs = parts[9].chunks(8)
        .map(|b| CacheRef { x: u16_at(b, 0) as i16 as i32, y: u16_at(b, 2) as i16 as i32, hash: i32_at(b, 4) })
        .collect();
    records(parts[10], 10, 12)?;
    let adds = parts[10].chunks(12)
        .map(|b| Ok(CacheAdd { r: read_region(b, 0, true)?, hash: i32_at(b, 8) }))
        .collect::<Result<_>>()?;
    Ok(ScreenFrame {
        number: int32_part(parts, 4)?, main, compressed: parts[2], copy_temp, scroll,
        jpeg: parts[7], aux, refs, adds,
    })
}

fn records(b: &[u8], part: usize, size: usize) -> Result<()> {
    if b.len() % size != 0 {
        return Err(screen_err(format!("malformed screen part {part}")));
    }
    if b.len() / size > MAX_RECORDS {
        return Err(screen_err(format!("screen part {part} has too many records")));
    }
    Ok(())
}

fn regions(b: &[u8], part: usize, signed: bool) -> Result<Vec<Region>> {
    records(b, part, 8)?;
    (0..b.len()).step_by(8).map(|off| read_region(b, off, signed)).collect()
}

fn read_region(b: &[u8], off: usize, signed: bool) -> Result<Region> {
    let read = |i| {
        let v = u16_at(b, off + i);
        if signed { v as i16 as i32 } else { v as i32 }
    };
    let r = Region { x: read(0), y: read(2), w: read(4), h: read(6) };
    check_geometry(r.w as i64, r.h as i64)?;
    Ok(r)
}

// --- ZstdScreenDecoder.swift ---

/// Keeps the screen dictionary loaded across missions.
pub struct ZstdDecoder(DCtx<'static>);

fn zstd(code: zstd_safe::SafeResult) -> Result<usize> {
    code.map_err(|c| format!("zstd: {}", zstd_safe::get_error_name(c)).into())
}

impl ZstdDecoder {
    pub fn new() -> Result<Self> {
        let mut d = DCtx::create();
        zstd(d.load_dictionary(SCREEN_DICTIONARY))?;
        // The UVC header rejects windows above 0x8000000 bytes.
        zstd(d.set_parameter(DParameter::WindowLogMax(27)))?;
        Ok(ZstdDecoder(d))
    }

    /// Resets the session (keeping the dictionary) and requires exactly `want` bytes.
    /// Concatenated frames continue automatically.
    pub fn decode(&mut self, src: &[u8], want: usize) -> Result<Vec<u8>> {
        zstd(self.0.reset(ResetDirective::SessionOnly))?;
        if src.is_empty() {
            return if want == 0 { Ok(vec![]) } else { Err(format!("screen pixels: expected {want} bytes, received 0").into()) };
        }
        let mut dst = vec![0u8; want + 1]; // one spare byte detects oversized output
        let mut input = InBuffer::around(src);
        let mut out = OutBuffer::around(&mut dst[..]);
        let mut hint;
        loop {
            let (before_in, before_out) = (input.pos, out.pos());
            hint = zstd(self.0.decompress_stream(&mut out, &mut input))?;
            if out.pos() == want + 1 || input.pos == src.len() || (input.pos == before_in && out.pos() == before_out) {
                break;
            }
        }
        let produced = out.pos();
        if produced != want {
            return Err(format!("screen pixels: expected {want} bytes, received {produced}").into());
        }
        if hint != 0 {
            return Err("zstd: incomplete frame".into());
        }
        dst.truncate(want);
        Ok(dst)
    }
}

// --- ModernScreenRenderer.swift ---

struct Cached {
    w: usize,
    h: usize,
    pixels: Vec<u8>, // packed top-down RGB555 LE
}

/// Keeps the main image as top-down RGBA and the converter buffer as bottom-up
/// RGB555 with DWORD-aligned rows.
/// shortcut: unlike Swift, a failed update is not rolled back; the session discards
/// the renderer and refreshes the screen, so the partial state is never reused.
pub struct Renderer {
    pub width: usize,
    pub height: usize,
    pub tile_size: usize,
    pub last: i32,
    /// Top-down RGBA.
    pub main: Vec<u8>,
    temp: Vec<u8>,
    stride: usize,
    cache: HashMap<i32, Cached>,
    order: Vec<i32>,
    cache_bytes: usize,
    zstd: ZstdDecoder,
}

/// A clipped copy: source origin, destination origin, size.
struct Window {
    sx: usize,
    sy: usize,
    dx: usize,
    dy: usize,
    w: usize,
    h: usize,
}

impl Renderer {
    pub fn new(width: usize, height: usize, tile_size: usize, last: i32) -> Result<Self> {
        check_geometry(width as i64, height as i64)?;
        if !(1..=255).contains(&tile_size) {
            return Err(screen_err(format!("invalid tile size {tile_size}")));
        }
        let stride = (width * 2 + 3) & !3;
        let mut main = vec![0u8; width * height * 4];
        main.iter_mut().skip(3).step_by(4).for_each(|a| *a = 255);
        Ok(Renderer {
            width, height, tile_size, last, main, temp: vec![0; stride * height], stride,
            cache: HashMap::new(), order: vec![], cache_bytes: 0, zstd: ZstdDecoder::new()?,
        })
    }

    pub fn set_tile_size(&mut self, parts: &[&[u8]]) -> Result<()> {
        match parts.get(1).and_then(|p| p.first()) {
            Some(&t) if t != 0 => {
                self.tile_size = t as usize;
                Ok(())
            }
            _ => Err(screen_err("malformed tile size")),
        }
    }

    pub fn apply(&mut self, m: &ScreenFrame) -> Result<()> {
        if m.number as i64 != self.last as i64 + 1 {
            return Err(screen_err(format!(
                "screen updates arrived out of order (expected {}, received {})", self.last as i64 + 1, m.number)));
        }
        let mut want = 0usize;
        for rc in &m.main {
            want += rc.w as usize * rc.h as usize * 2;
            if want > 128 * 1024 * 1024 {
                return Err(screen_err("screen update exceeds the supported size"));
            }
        }
        let raw = self.zstd.decode(m.compressed, want).map_err(|e| screen_err(e.to_string()))?;
        if let Some(s) = &m.scroll {
            self.main_to_temp(s.capture, s.capture.x, s.capture.y - s.delta);
            for &rc in &s.copy_back {
                self.temp_to_main(rc.x, rc.y, rc);
            }
        }
        for r in &m.refs {
            // Taken out and put back so copy_into_temp can borrow self mutably.
            let Some(item) = self.cache.remove(&r.hash) else {
                return Err(screen_err(format!("screen update refers to missing tile {}", r.hash)));
            };
            self.copy_into_temp(&item.pixels, item.w, item.h, r.x, r.y);
            self.cache.insert(r.hash, item);
            self.touch(r.hash);
        }
        for &rc in &m.copy_temp {
            self.temp_to_main(rc.x, rc.y, rc);
        }
        if !m.aux.is_empty() {
            let (atlas, aw, ah) = decode_atlas(m.jpeg)?;
            self.apply_atlas(&atlas, aw, ah, &m.aux)?;
        }
        let mut off = 0;
        for &rc in &m.main {
            let n = rc.w as usize * rc.h as usize * 2;
            self.copy_into_temp(&raw[off..off + n], rc.w as usize, rc.h as usize, 0, 0);
            self.temp_to_main(0, 0, rc);
            off += n;
        }
        for a in &m.adds {
            if !self.inside(a.r) {
                return Err(screen_err("invalid cached tile rectangle"));
            }
            self.main_to_temp(a.r, a.r.x, a.r.y);
            if self.cache.contains_key(&a.hash) {
                continue;
            }
            let px = self.extract_temp(a.r);
            if px.len() > MAX_CACHE_BYTES - self.cache_bytes {
                return Err(screen_err("screen image cache is full"));
            }
            self.cache_bytes += px.len();
            self.cache.insert(a.hash, Cached { w: a.r.w as usize, h: a.r.h as usize, pixels: px });
            self.order.push(a.hash);
        }
        while self.order.len() > MAX_CACHE_ENTRIES {
            let h = self.order.remove(0);
            if let Some(c) = self.cache.remove(&h) {
                self.cache_bytes -= c.pixels.len();
            }
        }
        self.last = m.number;
        Ok(())
    }

    fn touch(&mut self, hash: i32) {
        self.order.retain(|&h| h != hash);
        self.order.push(hash);
    }

    /// Clips source and destination together, keeping their offset.
    fn clip(&self, sx: i32, sy: i32, dx: i32, dy: i32, w: i32, h: i32) -> Option<Window> {
        let (sw, sh) = (self.width as i32, self.height as i32);
        let left = 0.max(-sx).max(-dx);
        let top = 0.max(-sy).max(-dy);
        let right = w.min(sw - sx).min(sw - dx);
        let bottom = h.min(sh - sy).min(sh - dy);
        if left >= right || top >= bottom {
            return None;
        }
        let u = |v: i32| v as usize;
        Some(Window { sx: u(sx + left), sy: u(sy + top), dx: u(dx + left), dy: u(dy + top), w: u(right - left), h: u(bottom - top) })
    }

    /// ScreenRectangleBuffer.copyRectangle: packed top-down RGB555 into bottom-up rows.
    fn copy_into_temp(&mut self, src: &[u8], w: usize, h: usize, x: i32, y: i32) {
        let (wi, hi) = (w as i32, h as i32);
        if x >= self.width as i32 || y >= self.height as i32 || x <= -wi || y <= -hi {
            return;
        }
        let (sx, sy) = ((-x).max(0) as usize, (-y).max(0) as usize);
        let (dx, dy) = (x.max(0) as usize, y.max(0) as usize);
        let (cw, ch) = ((w - sx).min(self.width - dx), (h - sy).min(self.height - dy));
        for row in 0..ch {
            let s = (sy + row) * w * 2 + sx * 2;
            let d = (self.height - 1 - (dy + row)) * self.stride + dx * 2;
            self.temp[d..d + cw * 2].copy_from_slice(&src[s..s + cw * 2]);
        }
    }

    fn main_to_temp(&mut self, src: Region, dx: i32, dy: i32) {
        let Some(c) = self.clip(src.x, src.y, dx, dy, src.w, src.h) else { return };
        let mut packed = vec![0u8; c.w * c.h * 2];
        for row in 0..c.h {
            let in_off = ((c.sy + row) * self.width + c.sx) * 4;
            for x in 0..c.w {
                let p = &self.main[in_off + x * 4..];
                let v = (p[2] >> 3) as u16 | ((p[1] >> 3) as u16) << 5 | ((p[0] >> 3) as u16) << 10;
                let o = (row * c.w + x) * 2;
                packed[o..o + 2].copy_from_slice(&v.to_le_bytes());
            }
        }
        self.copy_into_temp(&packed, c.w, c.h, c.dx as i32, c.dy as i32);
    }

    fn temp_to_main(&mut self, sx: i32, sy: i32, dst: Region) {
        let Some(c) = self.clip(sx, sy, dst.x, dst.y, dst.w, dst.h) else { return };
        let expand5 = |v: u16| (v << 3 | v >> 2) as u8;
        for row in 0..c.h {
            let in_off = (self.height - 1 - (c.sy + row)) * self.stride + c.sx * 2;
            let out_off = ((c.dy + row) * self.width + c.dx) * 4;
            for x in 0..c.w {
                let v = u16_at(&self.temp, in_off + x * 2);
                let o = out_off + x * 4;
                self.main[o..o + 4].copy_from_slice(&[expand5(v >> 10 & 31), expand5(v >> 5 & 31), expand5(v & 31), 255]);
            }
        }
    }

    fn extract_temp(&self, rc: Region) -> Vec<u8> {
        let (x, y, w, h) = (rc.x as usize, rc.y as usize, rc.w as usize, rc.h as usize);
        let mut out = Vec::with_capacity(w * h * 2);
        for row in 0..h {
            let s = (self.height - 1 - y - row) * self.stride + x * 2;
            out.extend_from_slice(&self.temp[s..s + w * 2]);
        }
        out
    }

    fn inside(&self, rc: Region) -> bool {
        let (w, h) = (self.width as i32, self.height as i32);
        rc.x >= 0 && rc.y >= 0 && rc.w > 0 && rc.h > 0 && rc.w <= w && rc.h <= h && rc.x <= w - rc.w && rc.y <= h - rc.h
    }

    /// Walks atlas tiles down each column (bottom-up rows), then to the next column.
    fn apply_atlas(&mut self, atlas: &[u8], aw: usize, ah: usize, rects: &[Region]) -> Result<()> {
        let (mut col, mut sy, mut tiles) = (0usize, 0usize, 0usize);
        let t = self.tile_size;
        for &rc in rects {
            if !self.inside(rc) {
                return Err(screen_err("invalid screen image rectangle"));
            }
            let (rx, ry, rw, rh) = (rc.x as usize, rc.y as usize, rc.w as usize, rc.h as usize);
            for dx in (0..rw).step_by(t) {
                for dy in (0..rh).step_by(t) {
                    tiles += 1;
                    if tiles > MAX_AUX_TILES {
                        return Err(screen_err("too many screen image tiles"));
                    }
                    let (tw, th) = (t.min(rw - dx), t.min(rh - dy));
                    if sy + th > ah {
                        sy = 0;
                        col += 1;
                    }
                    let sx = col * t;
                    if tw > aw || th > ah || sx > aw - tw || sy > ah - th {
                        return Err(screen_err("screen update contains an invalid image tile"));
                    }
                    for row in 0..th {
                        let s = ((ah - 1 - sy - row) * aw + sx) * 4;
                        let d = ((ry + dy + row) * self.width + rx + dx) * 4;
                        self.main[d..d + tw * 4].copy_from_slice(&atlas[s..s + tw * 4]);
                    }
                    sy += th;
                }
            }
        }
        Ok(())
    }
}

/// Decodes the JPEG atlas to RGBA.
fn decode_atlas(data: &[u8]) -> Result<(Vec<u8>, usize, usize)> {
    let bad = || screen_err("screen image could not be decoded");
    let mut d = jpeg_decoder::Decoder::new(data);
    d.read_info().map_err(|_| bad())?;
    let info = d.info().ok_or_else(bad)?;
    let (w, h) = (info.width as i64, info.height as i64);
    if w <= 0 || h <= 0 || w > MAX_ATLAS_SIDE || h > MAX_ATLAS_SIDE || w > MAX_PIXELS / h {
        return Err(screen_err("screen image exceeds the supported size"));
    }
    let px = d.decode().map_err(|_| bad())?;
    let rgba: Vec<u8> = match info.pixel_format {
        jpeg_decoder::PixelFormat::RGB24 => px.chunks(3).flat_map(|p| [p[0], p[1], p[2], 255]).collect(),
        jpeg_decoder::PixelFormat::L8 => px.iter().flat_map(|&l| [l, l, l, 255]).collect(),
        _ => return Err(bad()),
    };
    Ok((rgba, w as usize, h as usize))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    pub fn words(v: &[i32]) -> Vec<u8> {
        v.iter().flat_map(|&x| (x as i16 as u16).to_le_bytes()).collect()
    }

    pub fn long(v: i32) -> Vec<u8> {
        v.to_le_bytes().to_vec()
    }

    fn cat(a: &[u8], b: &[u8]) -> Vec<u8> {
        [a, b].concat()
    }

    /// A hand-built single-segment zstd frame holding one raw block.
    fn raw_zstd(b: &[u8]) -> Vec<u8> {
        let h = b.len() << 3 | 1;
        let mut out = vec![0x28, 0xb5, 0x2f, 0xfd, 0x20, b.len() as u8, h as u8, (h >> 8) as u8, 0];
        out.extend_from_slice(b);
        out
    }

    #[derive(Default)]
    pub struct Fp {
        pub seq: i32,
        pub rects: Vec<i32>,
        pub copy: Vec<i32>,
        pub scroll: Vec<i32>,
        pub aux: Vec<i32>,
        pub pixels: Vec<u8>,
        pub jpeg: Vec<u8>,
        pub references: Vec<u8>,
        pub adds: Vec<u8>,
    }

    pub fn parts(p: &Fp) -> Vec<Vec<u8>> {
        let seq = if p.seq == 0 { 1 } else { p.seq };
        let px = if p.pixels.is_empty() { vec![] } else { raw_zstd(&p.pixels) };
        vec![vec![1], words(&p.rects), px, vec![], long(seq), words(&p.copy), words(&p.scroll),
             p.jpeg.clone(), words(&p.aux), p.references.clone(), p.adds.clone()]
    }

    fn apply(r: &mut Renderer, p: Fp) -> Result<()> {
        let owned = parts(&p);
        let refs: Vec<&[u8]> = owned.iter().map(|v| &v[..]).collect();
        r.apply(&decode_screen_frame(&refs).unwrap())
    }

    fn bgr(r: &Renderer) -> Vec<u8> {
        r.main.chunks(4).flat_map(|p| [p[2], p[1], p[0]]).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn is_screen_err(r: Result<()>) -> bool {
        r.is_err_and(|e| e.is::<ScreenError>())
    }

    const JPEG_FIXTURE: &str = "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/2wBDAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/wAARCAACAAIDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD8KP8Ahr79rP8A6Oh/aJ/8PZ8Sv/mmooor+fz6xdPl/wC4z//Z";

    fn jpeg() -> Vec<u8> {
        STANDARD.decode(JPEG_FIXTURE).unwrap()
    }

    #[test]
    fn zstd_dictionary_survives_mission_reset() {
        let compressed = STANDARD.decode("KLUv/QdYEL2gPS0BAOhNYWNWaWV3ZXIgZGljdGlvbmFyeSBmaXh0dXJlCgEA0Qz4ygnbOEGJ").unwrap();
        let want = "MacViewer dictionary fixture\n".repeat(100);
        let mut z = ZstdDecoder::new().unwrap();
        for _ in 0..2 {
            assert_eq!(z.decode(&compressed, want.len()).unwrap(), want.as_bytes());
        }
        assert!(z.decode(&compressed[..compressed.len() - 3], want.len()).is_err(), "truncated frame accepted");
        let twice = cat(&compressed, &compressed);
        assert!(z.decode(&twice, want.len()).is_err(), "oversized output accepted");
        assert_eq!(z.decode(&twice, 2 * want.len()).unwrap().len(), 2 * want.len());
    }

    #[test]
    fn screen_parts_signedness() {
        let owned = parts(&Fp {
            seq: -7, rects: vec![-1, 2, 3, 4], copy: vec![-1, -2, 3, 4], scroll: vec![-5, -6, 7, 8, 9, 10, 11, 12, 13],
            jpeg: vec![0xaa], aux: vec![-14, 15, 16, 17], references: cat(&words(&[-18, 19]), &long(-20)),
            adds: cat(&words(&[-21, 22, 23, 24]), &long(-25)), ..Default::default()
        });
        let refs: Vec<&[u8]> = owned.iter().map(|v| &v[..]).collect();
        let f = decode_screen_frame(&refs).unwrap();
        let s = f.scroll.as_ref().unwrap();
        assert_eq!(f.number, -7);
        assert_eq!(f.main[0], Region { x: 65535, y: 2, w: 3, h: 4 });
        assert_eq!(f.copy_temp[0], Region { x: -1, y: -2, w: 3, h: 4 });
        assert_eq!((s.delta, s.capture, s.copy_back[0]), (-5, Region { x: -6, y: 7, w: 8, h: 9 }, Region { x: 10, y: 11, w: 12, h: 13 }));
        assert_eq!(f.aux[0], Region { x: -14, y: 15, w: 16, h: 17 });
        assert_eq!(f.refs[0], CacheRef { x: -18, y: 19, hash: -20 });
        assert_eq!(f.adds[0], CacheAdd { r: Region { x: -21, y: 22, w: 23, h: 24 }, hash: -25 });
    }

    #[test]
    fn rgb555_matches_windows_gdi() {
        let raw = unhex("00000100020003000400050006000700080009000a000b000c000d000e000f0010001100120013001400150016001700180019001a001b001c001d001e001f00");
        let want = unhex("0000000800001000001800002100002900003100003900004200004a00005200005a00006300006b00007300007b00008400008c00009400009c0000a50000ad0000b50000bd0000c60000ce0000d60000de0000e70000ef0000f70000ff0000");
        let mut r = Renderer::new(32, 1, 16, 0).unwrap();
        apply(&mut r, Fp { rects: vec![0, 0, 32, 1], pixels: raw, ..Default::default() }).unwrap();
        assert_eq!(bgr(&r), want);
    }

    #[test]
    fn reset_baseline_and_sequence() {
        let mut r = Renderer::new(1, 1, 16, RESET_FRAME_NUMBER).unwrap();
        let mut owned = parts(&Fp { rects: vec![0, 0, 1, 1], pixels: words(&[0x03e0]), ..Default::default() });
        owned[4] = vec![0x02, 0, 0, 0x80];
        let refs: Vec<&[u8]> = owned.iter().map(|v| &v[..]).collect();
        let f = decode_screen_frame(&refs).unwrap();
        r.apply(&f).unwrap();
        assert_eq!(bgr(&r), [0, 255, 0]);
        assert!(is_screen_err(r.apply(&f)), "replayed frame accepted");
    }

    #[test]
    fn padded_temporary_rows_and_clipping() {
        let mut r = Renderer::new(3, 2, 16, 0).unwrap();
        apply(&mut r, Fp { rects: vec![1, 0, 3, 2], pixels: words(&[0x7c00, 0x03e0, 0x001f, 0x7fff, 0, 0x7c00]), ..Default::default() }).unwrap();
        assert_eq!(bgr(&r), unhex("0000000000ff00ff00000000ffffff000000"));
    }

    #[test]
    fn scroll_copies_from_main_before_copy_back() {
        let mut r = Renderer::new(1, 3, 16, 0).unwrap();
        apply(&mut r, Fp { rects: vec![0, 0, 1, 3], pixels: words(&[0x7c00, 0x03e0, 0x001f]), ..Default::default() }).unwrap();
        apply(&mut r, Fp { seq: 2, scroll: vec![1, 0, 0, 1, 3, 0, 0, 1, 2], ..Default::default() }).unwrap();
        assert_eq!(bgr(&r), unhex("00ff00ff0000ff0000"));
    }

    #[test]
    fn jpeg_atlas_is_bottom_up_column_major() {
        let mut r = Renderer::new(4, 1, 1, 0).unwrap();
        apply(&mut r, Fp { jpeg: jpeg(), aux: vec![0, 0, 3, 1, 3, 0, 1, 1], ..Default::default() }).unwrap();
        let native = [24, 54, 59, 161, 191, 196, 24, 54, 59, 161, 191, 196];
        for (i, got) in bgr(&r).into_iter().enumerate() {
            assert!((got as i32 - native[i]).abs() <= 8, "byte {i} = {got}, native {}", native[i]); // lossy decoders differ slightly
        }
    }

    #[test]
    fn pipeline_cache_copy_jpeg_main_capture_order() {
        let mut r = Renderer::new(3, 2, 1, 0).unwrap();
        apply(&mut r, Fp { rects: vec![0, 0, 1, 1], pixels: words(&[0x7c00]), adds: cat(&words(&[0, 0, 1, 1]), &long(10)), ..Default::default() }).unwrap();
        let adds = [words(&[2, 0, 1, 1]), long(20), words(&[2, 1, 1, 1]), long(10)].concat();
        apply(&mut r, Fp {
            seq: 2, rects: vec![2, 1, 1, 1], pixels: words(&[0x7fff]), copy: vec![1, 0, 1, 1], jpeg: jpeg(),
            aux: vec![2, 0, 1, 2], references: cat(&words(&[1, 0]), &long(10)), adds, ..Default::default()
        }).unwrap();
        let second = bgr(&r);
        assert_eq!((&second[3..6], &second[15..18]), (&[0, 0, 255][..], &[255, 255, 255][..]));
        let jpeg_pixel = second[6..9].to_vec();
        let refs = [words(&[0, 1]), long(20), words(&[1, 1]), long(10)].concat();
        apply(&mut r, Fp { seq: 3, copy: vec![0, 1, 1, 1, 1, 1, 1, 1], references: refs, ..Default::default() }).unwrap();
        let third = bgr(&r);
        for (i, c) in jpeg_pixel.iter().enumerate() {
            assert_eq!(third[9 + i], (c & 0xf8) | (c >> 5));
        }
        assert_eq!(&third[12..15], &[0, 0, 255]);
        assert_eq!((r.cache.len(), r.cache_bytes), (2, 4));
    }

    #[test]
    fn cache_thousand_entry_limit_and_recency() {
        let mut r = Renderer::new(1, 1, 16, 0).unwrap();
        let adds: Vec<u8> = (0..1000).flat_map(|h| cat(&words(&[0, 0, 1, 1]), &long(h))).collect();
        apply(&mut r, Fp { adds, ..Default::default() }).unwrap();
        assert_eq!(r.cache.len(), 1000);
        apply(&mut r, Fp { seq: 2, references: cat(&words(&[0, 0]), &long(0)), adds: cat(&words(&[0, 0, 1, 1]), &long(1000)), ..Default::default() }).unwrap();
        assert_eq!(r.cache.len(), 1000);
        assert!(apply(&mut r, Fp { seq: 3, references: cat(&words(&[0, 0]), &long(1)), ..Default::default() }).is_err(), "evicted hash 1 still cached");
        apply(&mut r, Fp { seq: 3, references: cat(&words(&[0, 0]), &long(0)), ..Default::default() }).expect("recently used hash 0 was evicted");
    }

    #[test]
    fn invalid_updates_are_screen_errors() {
        let mut r = Renderer::new(2, 1, 16, 0).unwrap();
        assert!(is_screen_err(apply(&mut r, Fp { rects: vec![0, 0, 2, 1], pixels: words(&[0x001f]), ..Default::default() })), "length mismatch");
        assert!(is_screen_err(apply(&mut r, Fp { jpeg: vec![1, 2, 3], aux: vec![0, 0, 1, 1], ..Default::default() })), "invalid jpeg");
        assert!(is_screen_err(apply(&mut r, Fp { seq: 2, ..Default::default() })), "sequence");
        assert!(decode_screen_init(&[&[0], &long(8193), &long(1)]).is_err(), "oversized screen accepted");
    }
}
