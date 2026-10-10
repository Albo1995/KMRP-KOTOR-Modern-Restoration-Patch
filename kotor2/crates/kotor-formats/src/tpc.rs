//! TPC textures.
//!
//! # Layout (from public documentation: xoreos `tpc.cpp`, PyKotor; and KMRP's
//! own `tools/build_icon_tpc.py`, which writes TPCs the game loads)
//!
//! A 128-byte header: data size (u32; for DXT the size of the first mip
//! level, 0 for uncompressed), alpha test (f32), width (u16), height (u16),
//! encoding (u8: 1 grey, 2 RGB, 4 RGBA, 12 swizzled BGRA), mip count (u8) and
//! 114 reserved bytes. Encoding 2 with a non-zero data size is DXT1, encoding
//! 4 with a non-zero data size is DXT5. Then the mip chain (largest first),
//! then optional TXI text to the end of the file.
//!
//! Rows are stored bottom-up (KMRP measured this: its icons shipped upside
//! down once when they were written top-down). A texture whose height is six
//! times its width is a cube map of six square faces, each with its own mip
//! chain. A texture whose TXI says `proceduretype cycle` with `numx`/`numy`
//! is treated as `numx * numy` frames, each with its own mip chain, when that
//! layout matches the file size (from xoreos; unverified against the game).
//!
//! # Round trips
//!
//! The image data and the TXI are kept as raw bytes, so [`Tpc::to_bytes`] is
//! byte-exact by construction. The split between them is computed from the
//! header; [`Tpc::levels`] describes the image data without changing it.

use crate::binio::{Bytes, Put};
use crate::error::{Error, Result};
use crate::text;
use crate::txi::Txi;

const FMT: &str = "TPC";
const HEADER_LEN: usize = 128;

/// Pixel format of the image data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TpcFormat {
    /// 8-bit grey.
    Grey,
    /// 24-bit RGB.
    Rgb,
    /// 32-bit RGBA.
    Rgba,
    /// 32-bit swizzled BGRA (Xbox).
    SwizzledBgra,
    /// BC1.
    Dxt1,
    /// BC3.
    Dxt5,
}

impl TpcFormat {
    /// Bytes for one level.
    /// Saturates at `usize::MAX` rather than overflowing on 32-bit targets.
    pub fn level_size(self, width: usize, height: usize) -> usize {
        let (w, h) = (width.max(1) as u64, height.max(1) as u64);
        let blocks = w.div_ceil(4) * h.div_ceil(4);
        let bytes = match self {
            TpcFormat::Grey => w * h,
            TpcFormat::Rgb => w * h * 3,
            TpcFormat::Rgba | TpcFormat::SwizzledBgra => w * h * 4,
            TpcFormat::Dxt1 => blocks * 8,
            TpcFormat::Dxt5 => blocks * 16,
        };
        usize::try_from(bytes).unwrap_or(usize::MAX)
    }

    /// A short name.
    pub fn name(self) -> &'static str {
        match self {
            TpcFormat::Grey => "grey8",
            TpcFormat::Rgb => "rgb24",
            TpcFormat::Rgba => "rgba32",
            TpcFormat::SwizzledBgra => "bgra32-swizzled",
            TpcFormat::Dxt1 => "dxt1",
            TpcFormat::Dxt5 => "dxt5",
        }
    }
}

/// One mip level of one layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TpcLevel {
    /// Layer (cube face or animation frame; 0 otherwise).
    pub layer: usize,
    /// Mip level (0 = largest).
    pub level: usize,
    /// Width in pixels.
    pub width: usize,
    /// Height in pixels.
    pub height: usize,
    /// Offset into [`Tpc::data`].
    pub offset: usize,
    /// Bytes.
    pub size: usize,
}

/// How the image data divides into layers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TpcKind {
    /// One image.
    Single,
    /// Six cube-map faces.
    CubeMap,
    /// Animation frames (`numx * numy`).
    Animated {
        /// Frames across.
        numx: usize,
        /// Frames down.
        numy: usize,
    },
}

/// A TPC texture.
#[derive(Clone, Debug, PartialEq)]
pub struct Tpc {
    /// Header data size.
    pub data_size: u32,
    /// Alpha test threshold.
    pub alpha_test: f32,
    /// Header width.
    pub width: u16,
    /// Header height.
    pub height: u16,
    /// Encoding byte.
    pub encoding: u8,
    /// Header mip count.
    pub mip_count: u8,
    /// The 114 reserved header bytes.
    pub reserved: Vec<u8>,
    /// Image data (all layers and levels).
    pub data: Vec<u8>,
    /// Trailing TXI bytes, raw.
    pub txi: Vec<u8>,
}

fn is_texty(b: &[u8]) -> bool {
    b.iter()
        .all(|&c| matches!(c, 0x20..=0x7E | b'\t' | b'\r' | b'\n' | 0))
}

fn cycle_frames(txi: &Txi) -> Option<(usize, usize)> {
    if !txi.get("proceduretype")?.eq_ignore_ascii_case("cycle") {
        return None;
    }
    let nx = txi.get_f32("numx")? as usize;
    let ny = txi.get_f32("numy")? as usize;
    (nx >= 1 && ny >= 1 && nx * ny > 1).then_some((nx, ny))
}

impl Tpc {
    /// The pixel format the header describes.
    pub fn format(&self) -> Result<TpcFormat> {
        let compressed = self.data_size != 0;
        Ok(match (self.encoding, compressed) {
            (2, true) => TpcFormat::Dxt1,
            (4, true) => TpcFormat::Dxt5,
            (1, false) => TpcFormat::Grey,
            (2, false) => TpcFormat::Rgb,
            (4, false) => TpcFormat::Rgba,
            (12, _) => TpcFormat::SwizzledBgra,
            (e, c) => {
                return Err(Error::unsupported(
                    FMT,
                    format!(
                        "encoding {e} with data size {} ({})",
                        self.data_size,
                        if c { "compressed" } else { "uncompressed" }
                    ),
                ))
            }
        })
    }

    fn chain(format: TpcFormat, w: usize, h: usize, mips: usize) -> usize {
        (0..mips)
            .map(|l| format.level_size(w >> l, h >> l))
            .fold(0usize, usize::saturating_add)
    }

    /// Layers and per-layer size for a kind.
    fn dims(&self, kind: TpcKind) -> (usize, usize, usize) {
        let (w, h) = (usize::from(self.width), usize::from(self.height));
        match kind {
            TpcKind::Single => (1, w, h),
            TpcKind::CubeMap => (6, w, w),
            TpcKind::Animated { numx, numy } => (numx * numy, w / numx, h / numy),
        }
    }

    /// Largest mip count <= the header's whose chain fits in `avail` bytes.
    fn fitting_mips(&self, format: TpcFormat, kind: TpcKind, avail: usize) -> Option<usize> {
        let (layers, w, h) = self.dims(kind);
        (1..=usize::from(self.mip_count).max(1))
            .rev()
            .find(|&m| layers.saturating_mul(Tpc::chain(format, w, h, m)) <= avail)
    }

    fn base_kind(&self) -> TpcKind {
        if self.width > 0 && usize::from(self.height) == 6 * usize::from(self.width) {
            TpcKind::CubeMap
        } else {
            TpcKind::Single
        }
    }

    /// How the data divides into layers.
    pub fn kind(&self) -> TpcKind {
        if let (Some((numx, numy)), Ok(format)) = (cycle_frames(&self.txi()), self.format()) {
            let kind = TpcKind::Animated { numx, numy };
            let (layers, w, h) = self.dims(kind);
            let m = usize::from(self.mip_count).max(1);
            if w > 0
                && h > 0
                && usize::from(self.width) % numx == 0
                && usize::from(self.height) % numy == 0
                && layers.saturating_mul(Tpc::chain(format, w, h, m)) == self.data.len()
            {
                return kind;
            }
        }
        self.base_kind()
    }

    /// Parse.
    pub fn read(data: &[u8]) -> Result<Tpc> {
        let b = Bytes::new(data, FMT);
        b.slice(0, HEADER_LEN)?;
        let mut t = Tpc {
            data_size: b.u32(0)?,
            alpha_test: b.f32(4)?,
            width: b.u16(8)?,
            height: b.u16(10)?,
            encoding: b.u8(12)?,
            mip_count: b.u8(13)?,
            reserved: b.slice(14, 114)?.to_vec(),
            data: Vec::new(),
            txi: Vec::new(),
        };
        if t.width == 0 || t.height == 0 {
            return Err(Error::invalid(
                FMT,
                format!("zero size {}x{}", t.width, t.height),
            ));
        }
        let format = t.format()?;
        let body = &data[HEADER_LEN..];
        let kind = t.base_kind();
        let (layers, w, h) = t.dims(kind);
        let m = t
            .fitting_mips(format, kind, body.len())
            .ok_or_else(|| Error::Truncated {
                format: FMT,
                offset: HEADER_LEN,
                needed: layers * format.level_size(w, h),
                len: data.len(),
            })?;
        let mut split = layers.saturating_mul(Tpc::chain(format, w, h, m));
        if !is_texty(&body[split..]) {
            if let Some(alt) = Tpc::animated_split(&t, format, body) {
                split = alt;
            }
        }
        t.data = body[..split].to_vec();
        t.txi = body[split..].to_vec();
        Ok(t)
    }

    /// If the file ends in a TXI describing an animation whose frame layout
    /// accounts exactly for the bytes before it, the split point.
    fn animated_split(t: &Tpc, format: TpcFormat, body: &[u8]) -> Option<usize> {
        let text_start = body
            .iter()
            .rposition(|&c| !matches!(c, 0x20..=0x7E | b'\t' | b'\r' | b'\n' | 0))
            .map_or(0, |p| p + 1);
        let (numx, numy) = cycle_frames(&Txi::parse_bytes(&body[text_start..]))?;
        if usize::from(t.width) % numx != 0 || usize::from(t.height) % numy != 0 {
            return None;
        }
        let kind = TpcKind::Animated { numx, numy };
        let (layers, w, h) = t.dims(kind);
        let m = usize::from(t.mip_count).max(1);
        let split = layers.saturating_mul(Tpc::chain(format, w, h, m));
        let fits = split <= body.len() && is_texty(&body[split..]);
        (fits && cycle_frames(&Txi::parse_bytes(&body[split..])) == Some((numx, numy)))
            .then_some(split)
    }

    /// The mip levels present in [`Tpc::data`], layer by layer. Levels the
    /// header promises but the data does not hold are left out.
    pub fn levels(&self) -> Result<Vec<TpcLevel>> {
        let format = self.format()?;
        let kind = self.kind();
        let (layers, w, h) = self.dims(kind);
        let m = self
            .fitting_mips(format, kind, self.data.len())
            .unwrap_or(0);
        let mut out = Vec::with_capacity(layers * m);
        let mut offset = 0;
        for layer in 0..layers {
            for level in 0..m {
                let (lw, lh) = ((w >> level).max(1), (h >> level).max(1));
                let size = format.level_size(lw, lh);
                out.push(TpcLevel {
                    layer,
                    level,
                    width: lw,
                    height: lh,
                    offset,
                    size,
                });
                offset += size;
            }
        }
        Ok(out)
    }

    /// The trailing TXI as text.
    pub fn txi_text(&self) -> String {
        let end = self.txi.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
        text::decode(&self.txi[..end])
    }

    /// The trailing TXI, parsed.
    pub fn txi(&self) -> Txi {
        Txi::parse_bytes(&self.txi)
    }

    /// Decode one level to RGBA8, rows in stored (bottom-up) order.
    pub fn decode_rgba(&self, level: &TpcLevel) -> Result<Vec<u8>> {
        let format = self.format()?;
        let src = self
            .data
            .get(level.offset..level.offset + level.size)
            .ok_or_else(|| Error::invalid(FMT, "level outside the image data"))?;
        let (w, h) = (level.width, level.height);
        let mut out = vec![0u8; w * h * 4];
        match format {
            TpcFormat::Grey => {
                for (o, &g) in out.chunks_exact_mut(4).zip(src) {
                    o.copy_from_slice(&[g, g, g, 255]);
                }
            }
            TpcFormat::Rgb => {
                for (o, p) in out.chunks_exact_mut(4).zip(src.chunks_exact(3)) {
                    o.copy_from_slice(&[p[0], p[1], p[2], 255]);
                }
            }
            TpcFormat::Rgba => out.copy_from_slice(&src[..w * h * 4]),
            TpcFormat::SwizzledBgra => {
                return Err(Error::unsupported(FMT, "decoding swizzled (Xbox) BGRA"));
            }
            TpcFormat::Dxt1 | TpcFormat::Dxt5 => {
                let bs = if format == TpcFormat::Dxt1 { 8 } else { 16 };
                let bw = w.div_ceil(4);
                for (i, block) in src.chunks_exact(bs).enumerate() {
                    let (bx, by) = (i % bw, i / bw);
                    let px = if format == TpcFormat::Dxt1 {
                        decode_bc1(block.try_into().expect("8 bytes"), true)
                    } else {
                        decode_bc3(block.try_into().expect("16 bytes"))
                    };
                    for (j, p) in px.iter().enumerate() {
                        let (x, y) = (bx * 4 + j % 4, by * 4 + j / 4);
                        if x < w && y < h {
                            out[(y * w + x) * 4..][..4].copy_from_slice(p);
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// An uncompressed RGBA texture with one mip level. `rgba` rows are in
    /// stored (bottom-up) order.
    pub fn from_rgba(width: u16, height: u16, rgba: Vec<u8>, txi: &str) -> Result<Tpc> {
        if rgba.len() != usize::from(width) * usize::from(height) * 4 {
            return Err(Error::invalid(
                FMT,
                format!("{} bytes of pixels for {width}x{height}", rgba.len()),
            ));
        }
        Ok(Tpc {
            data_size: 0,
            alpha_test: 1.0,
            width,
            height,
            encoding: 4,
            mip_count: 1,
            reserved: vec![0; 114],
            data: rgba,
            txi: text::encode(txi, "TXI")?,
        })
    }

    /// Serialize (header, data, TXI).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.data.len() + self.txi.len());
        out.put_u32(self.data_size);
        out.put_f32(self.alpha_test);
        out.put_u16(self.width);
        out.put_u16(self.height);
        out.put_u8(self.encoding);
        out.put_u8(self.mip_count);
        let mut reserved = self.reserved.clone();
        reserved.resize(114, 0);
        out.extend_from_slice(&reserved);
        out.extend_from_slice(&self.data);
        out.extend_from_slice(&self.txi);
        Ok(out)
    }
}

fn rgb565(c: u16) -> [u8; 4] {
    let r = ((c >> 11) & 31) as u8;
    let g = ((c >> 5) & 63) as u8;
    let b = (c & 31) as u8;
    [
        (r << 3) | (r >> 2),
        (g << 2) | (g >> 4),
        (b << 3) | (b >> 2),
        255,
    ]
}

fn mix(a: [u8; 4], b: [u8; 4], wa: u16, wb: u16) -> [u8; 4] {
    let t = wa + wb;
    let f = |x: u8, y: u8| ((u16::from(x) * wa + u16::from(y) * wb) / t) as u8;
    [f(a[0], b[0]), f(a[1], b[1]), f(a[2], b[2]), 255]
}

/// Decode a BC1 block to 16 RGBA pixels (row-major within the block).
fn decode_bc1(block: &[u8; 8], allow_alpha: bool) -> [[u8; 4]; 16] {
    let c0 = u16::from_le_bytes([block[0], block[1]]);
    let c1 = u16::from_le_bytes([block[2], block[3]]);
    let (p0, p1) = (rgb565(c0), rgb565(c1));
    let palette = if c0 > c1 || !allow_alpha {
        [p0, p1, mix(p0, p1, 2, 1), mix(p0, p1, 1, 2)]
    } else {
        [p0, p1, mix(p0, p1, 1, 1), [0, 0, 0, 0]]
    };
    let bits = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
    let mut out = [[0u8; 4]; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = palette[((bits >> (2 * i)) & 3) as usize];
    }
    out
}

/// Decode a BC3 block.
fn decode_bc3(block: &[u8; 16]) -> [[u8; 4]; 16] {
    let (a0, a1) = (u16::from(block[0]), u16::from(block[1]));
    let mut alpha = [0u16; 8];
    alpha[0] = a0;
    alpha[1] = a1;
    if a0 > a1 {
        for i in 1..7u16 {
            alpha[usize::from(i) + 1] = ((7 - i) * a0 + i * a1) / 7;
        }
    } else {
        for i in 1..5u16 {
            alpha[usize::from(i) + 1] = ((5 - i) * a0 + i * a1) / 5;
        }
        alpha[6] = 0;
        alpha[7] = 255;
    }
    let mut bits = 0u64;
    for (i, &b) in block[2..8].iter().enumerate() {
        bits |= u64::from(b) << (8 * i);
    }
    let mut out = decode_bc1(block[8..16].try_into().expect("8 bytes"), false);
    for (i, o) in out.iter_mut().enumerate() {
        o[3] = alpha[((bits >> (3 * i)) & 7) as usize] as u8;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(data_size: u32, w: u16, h: u16, enc: u8, mips: u8) -> Vec<u8> {
        let mut v = Vec::new();
        v.put_u32(data_size);
        v.put_f32(1.0);
        v.put_u16(w);
        v.put_u16(h);
        v.put_u8(enc);
        v.put_u8(mips);
        v.resize(128, 0);
        v
    }

    #[test]
    fn dxt5_with_mips_and_txi() {
        // 8x8 DXT5, 4 mips: 64 + 16 + 16 + 16 bytes.
        let mut f = header(64, 8, 8, 4, 4);
        f.extend((0..112).map(|i| i as u8));
        f.extend_from_slice(b"mipmap 0\r\nblending additive\r\n");
        let t = Tpc::read(&f).unwrap();
        assert_eq!(t.format().unwrap(), TpcFormat::Dxt5);
        assert_eq!(t.data.len(), 112);
        let levels = t.levels().unwrap();
        assert_eq!(levels.len(), 4);
        assert_eq!(levels[3].width, 1);
        assert_eq!(levels[1].offset, 64);
        assert_eq!(t.txi().get("blending"), Some("additive"));
        assert_eq!(t.to_bytes().unwrap(), f);
    }

    #[test]
    fn header_overpromising_mips_still_splits() {
        // Claims 5 mips of 4x4 DXT1 (8 bytes each) but holds 2.
        let mut f = header(8, 4, 4, 2, 5);
        f.extend_from_slice(&[0xAA; 16]);
        let t = Tpc::read(&f).unwrap();
        assert_eq!(t.format().unwrap(), TpcFormat::Dxt1);
        assert_eq!(t.levels().unwrap().len(), 2);
        assert_eq!(t.to_bytes().unwrap(), f);
    }

    #[test]
    fn cube_map() {
        let mut f = header(0, 2, 12, 2, 1);
        f.extend(std::iter::repeat_n(9u8, 6 * 2 * 2 * 3));
        let t = Tpc::read(&f).unwrap();
        assert_eq!(t.kind(), TpcKind::CubeMap);
        assert_eq!(t.levels().unwrap().len(), 6);
        assert!(t.txi.is_empty());
    }

    #[test]
    fn animated() {
        // 8x4 DXT1 sheet, 2x1 frames of 4x4, 2 mips each: 2 * (8 + 8) = 32 bytes.
        // As a single image it would be 16 + 8 = 24 bytes, leaving binary.
        let mut f = header(16, 8, 4, 2, 2);
        f.extend_from_slice(&[0xFF; 32]);
        f.extend_from_slice(b"proceduretype cycle\r\nnumx 2\r\nnumy 1\r\nfps 8\r\n");
        let t = Tpc::read(&f).unwrap();
        assert_eq!(t.data.len(), 32);
        assert_eq!(t.kind(), TpcKind::Animated { numx: 2, numy: 1 });
        assert_eq!(t.levels().unwrap().len(), 4);
        assert_eq!(t.to_bytes().unwrap(), f);
    }

    #[test]
    fn decodes() {
        // One BC1 block, c0 = white, c1 = black, all index 1 (black) except pixel 0.
        let mut f = header(8, 4, 4, 2, 1);
        f.extend_from_slice(&[0xFF, 0xFF, 0, 0, 0b0101_0100, 0x55, 0x55, 0x55]);
        let t = Tpc::read(&f).unwrap();
        let px = t.decode_rgba(&t.levels().unwrap()[0]).unwrap();
        assert_eq!(&px[..4], &[255, 255, 255, 255]);
        assert_eq!(&px[4..8], &[0, 0, 0, 255]);
        // BC3 alpha: a0=255, a1=0, index 1 everywhere -> 0.
        let mut b = [0u8; 16];
        b[0] = 255;
        b[2..8].copy_from_slice(&[
            0b0100_1001,
            0b1001_0010,
            0b0010_0100,
            0b0100_1001,
            0b1001_0010,
            0b0010_0100,
        ]);
        assert!(decode_bc3(&b).iter().all(|p| p[3] == 0));
        let t = Tpc::from_rgba(1, 1, vec![1, 2, 3, 4], "mipmap 0\n").unwrap();
        let back = Tpc::read(&t.to_bytes().unwrap()).unwrap();
        assert_eq!(back, t);
        assert_eq!(
            back.decode_rgba(&back.levels().unwrap()[0]).unwrap(),
            [1, 2, 3, 4]
        );
    }

    #[test]
    fn errors() {
        assert!(Tpc::read(&[0; 10]).is_err());
        assert!(Tpc::read(&header(0, 0, 4, 4, 1)).is_err());
        assert!(Tpc::read(&header(0, 4, 4, 9, 1)).is_err());
        assert!(Tpc::read(&header(0, 4, 4, 4, 1)).is_err(), "no pixel data");
    }
}
