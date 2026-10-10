//! Truevision TGA, the uncompressed texture format KotOR loads from
//! `Override` alongside TPC.
//!
//! Supported: image types 2 (true-colour), 3 (grey), 10 (RLE true-colour) and
//! 11 (RLE grey), at 8, 16 (A1R5G5B5), 24 and 32 bits per pixel, any origin.
//! Colour-mapped images (types 1 and 9) are rejected.
//!
//! # Round trips
//!
//! The header, image ID, any colour map bytes and anything after the pixels
//! (TGA 2.0 extension area and footer) are kept. Uncompressed images come
//! back byte-identical. RLE images are re-encoded with packets that never
//! cross a scanline; a file written by this module round-trips exactly, one
//! from another encoder may not.

use crate::binio::{Bytes, Put};
use crate::error::{Error, Result};

const FMT: &str = "TGA";

/// A TGA image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tga {
    /// Image type (2, 3, 10 or 11).
    pub image_type: u8,
    /// Bits per pixel (8, 16, 24 or 32).
    pub bits: u8,
    /// Descriptor: alpha bits in 0..4, 0x10 right-to-left, 0x20 top-to-bottom.
    pub descriptor: u8,
    /// Width.
    pub width: u16,
    /// Height.
    pub height: u16,
    /// X origin (informational).
    pub x_origin: u16,
    /// Y origin (informational).
    pub y_origin: u16,
    /// Image ID bytes.
    pub id: Vec<u8>,
    /// Colour-map type byte and its 5-byte spec, kept verbatim.
    pub colormap_header: [u8; 6],
    /// Raw colour-map bytes (unused by true-colour images, kept verbatim).
    pub colormap: Vec<u8>,
    /// Pixels as RGBA8, **top row first**, left to right.
    pub pixels: Vec<u8>,
    /// Bytes after the pixel data.
    pub trailer: Vec<u8>,
}

impl Tga {
    /// A 32-bit image, stored bottom-up with 8 alpha bits (descriptor 0x08),
    /// optionally RLE. `pixels` is RGBA8, top row first.
    pub fn new_rgba(width: u16, height: u16, pixels: Vec<u8>, rle: bool) -> Result<Tga> {
        if pixels.len() != usize::from(width) * usize::from(height) * 4 {
            return Err(Error::invalid(
                FMT,
                format!("{} bytes of pixels for {width}x{height}", pixels.len()),
            ));
        }
        Ok(Tga {
            image_type: if rle { 10 } else { 2 },
            bits: 32,
            descriptor: 0x08,
            width,
            height,
            x_origin: 0,
            y_origin: 0,
            id: Vec::new(),
            colormap_header: [0; 6],
            colormap: Vec::new(),
            pixels,
            trailer: Vec::new(),
        })
    }

    fn bpp(&self) -> Result<usize> {
        let grey = matches!(self.image_type, 3 | 11);
        match (grey, self.bits) {
            (true, 8) => Ok(1),
            (false, 16) => Ok(2),
            (false, 24) => Ok(3),
            (false, 32) => Ok(4),
            _ => Err(Error::unsupported(
                FMT,
                format!(
                    "{} bits per pixel for image type {}",
                    self.bits, self.image_type
                ),
            )),
        }
    }

    /// Parse.
    pub fn read(data: &[u8]) -> Result<Tga> {
        let b = Bytes::new(data, FMT);
        b.slice(0, 18)?;
        let id_len = usize::from(b.u8(0)?);
        let mut colormap_header = [0u8; 6];
        colormap_header[0] = b.u8(1)?;
        colormap_header[1..].copy_from_slice(b.slice(3, 5)?);
        let image_type = b.u8(2)?;
        if !matches!(image_type, 2 | 3 | 10 | 11) {
            return Err(Error::unsupported(
                FMT,
                format!("image type {image_type} (only 2, 3, 10 and 11 are supported)"),
            ));
        }
        let cmap_len = usize::from(u16::from_le_bytes([colormap_header[3], colormap_header[4]]));
        let cmap_bits = usize::from(colormap_header[5]);
        let cmap_bytes = if colormap_header[0] != 0 {
            cmap_len * cmap_bits.div_ceil(8)
        } else {
            0
        };
        let mut t = Tga {
            image_type,
            bits: b.u8(16)?,
            descriptor: b.u8(17)?,
            width: b.u16(12)?,
            height: b.u16(14)?,
            x_origin: b.u16(8)?,
            y_origin: b.u16(10)?,
            id: b.slice(18, id_len)?.to_vec(),
            colormap_header,
            colormap: b.slice(18 + id_len, cmap_bytes)?.to_vec(),
            pixels: Vec::new(),
            trailer: Vec::new(),
        };
        let bpp = t.bpp()?;
        let (w, h) = (usize::from(t.width), usize::from(t.height));
        let n = w * h; // at most 65535^2, which fits even a 32-bit usize
        let too_big = || Error::invalid(FMT, format!("{w}x{h} is too large for this platform"));
        n.checked_mul(4).ok_or_else(too_big)?;
        let mut pos = 18 + id_len + cmap_bytes;
        let raw: Vec<u8> = if image_type < 8 {
            let s = b.slice(pos, n * bpp)?;
            pos += n * bpp;
            s.to_vec()
        } else {
            let mut out = Vec::with_capacity(n * bpp);
            while out.len() < n * bpp {
                let head = b.u8(pos)?;
                pos += 1;
                let count = usize::from(head & 0x7F) + 1;
                if head & 0x80 != 0 {
                    let px = b.slice(pos, bpp)?;
                    pos += bpp;
                    for _ in 0..count {
                        out.extend_from_slice(px);
                    }
                } else {
                    out.extend_from_slice(b.slice(pos, count * bpp)?);
                    pos += count * bpp;
                }
            }
            // A final packet that overshoots the last pixel is tolerated.
            out.truncate(n * bpp);
            out
        };
        t.trailer = data[pos..].to_vec();
        let mut pixels = vec![0u8; n * 4];
        for (i, px) in raw.chunks_exact(bpp).enumerate() {
            let (x, y) = t.image_xy(i % w.max(1), i / w.max(1));
            pixels[(y * w + x) * 4..][..4].copy_from_slice(&to_rgba(px));
        }
        t.pixels = pixels;
        Ok(t)
    }

    /// Image (top-down) coordinates of a stored pixel.
    fn image_xy(&self, sx: usize, sy: usize) -> (usize, usize) {
        let (w, h) = (usize::from(self.width), usize::from(self.height));
        let x = if self.descriptor & 0x10 != 0 {
            w - 1 - sx
        } else {
            sx
        };
        let y = if self.descriptor & 0x20 != 0 {
            sy
        } else {
            h - 1 - sy
        };
        (x, y)
    }

    /// Pixel rows in stored order, packed at the file's depth.
    fn stored(&self) -> Result<Vec<u8>> {
        let bpp = self.bpp()?;
        let (w, h) = (usize::from(self.width), usize::from(self.height));
        if self.pixels.len() != w * h * 4 {
            return Err(Error::invalid(
                FMT,
                format!("{} bytes of pixels for {w}x{h}", self.pixels.len()),
            ));
        }
        let mut out = Vec::with_capacity(w * h * bpp);
        for sy in 0..h {
            for sx in 0..w {
                let (x, y) = self.image_xy(sx, sy);
                let p = &self.pixels[(y * w + x) * 4..][..4];
                from_rgba(p, bpp, &mut out);
            }
        }
        Ok(out)
    }

    /// Serialize.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let bpp = self.bpp()?;
        let id_len = u8::try_from(self.id.len())
            .map_err(|_| Error::invalid(FMT, "image ID longer than 255 bytes"))?;
        let mut out = Vec::new();
        out.put_u8(id_len);
        out.put_u8(self.colormap_header[0]);
        out.put_u8(self.image_type);
        out.extend_from_slice(&self.colormap_header[1..]);
        out.put_u16(self.x_origin);
        out.put_u16(self.y_origin);
        out.put_u16(self.width);
        out.put_u16(self.height);
        out.put_u8(self.bits);
        out.put_u8(self.descriptor);
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.colormap);
        let raw = self.stored()?;
        if self.image_type < 8 {
            out.extend_from_slice(&raw);
        } else {
            let row = usize::from(self.width) * bpp;
            for line in raw.chunks(row.max(1)) {
                rle_encode(line, bpp, &mut out);
            }
        }
        out.extend_from_slice(&self.trailer);
        Ok(out)
    }
}

fn to_rgba(px: &[u8]) -> [u8; 4] {
    match px.len() {
        1 => [px[0], px[0], px[0], 255],
        2 => {
            let v = u16::from_le_bytes([px[0], px[1]]);
            let c = |s: u16| {
                let x = ((v >> s) & 31) as u8;
                (x << 3) | (x >> 2)
            };
            [c(10), c(5), c(0), if v & 0x8000 != 0 { 255 } else { 0 }]
        }
        3 => [px[2], px[1], px[0], 255],
        _ => [px[2], px[1], px[0], px[3]],
    }
}

fn from_rgba(p: &[u8], bpp: usize, out: &mut Vec<u8>) {
    match bpp {
        1 => out.push(p[0]),
        2 => {
            let c = |x: u8| u16::from(x >> 3);
            let v = (u16::from(p[3] >= 128) << 15) | (c(p[0]) << 10) | (c(p[1]) << 5) | c(p[2]);
            out.extend_from_slice(&v.to_le_bytes());
        }
        3 => out.extend_from_slice(&[p[2], p[1], p[0]]),
        _ => out.extend_from_slice(&[p[2], p[1], p[0], p[3]]),
    }
}

/// RLE-encode one scanline: runs of 2+ identical pixels become run packets.
fn rle_encode(line: &[u8], bpp: usize, out: &mut Vec<u8>) {
    let px: Vec<&[u8]> = line.chunks_exact(bpp).collect();
    let mut i = 0;
    while i < px.len() {
        let mut run = 1;
        while i + run < px.len() && run < 128 && px[i + run] == px[i] {
            run += 1;
        }
        if run >= 2 {
            out.push(0x80 | (run - 1) as u8);
            out.extend_from_slice(px[i]);
            i += run;
            continue;
        }
        let start = i;
        while i < px.len() && i - start < 128 && !(i + 1 < px.len() && px[i + 1] == px[i]) {
            i += 1;
        }
        if i == start {
            i += 1;
        }
        out.push((i - start - 1) as u8);
        for p in &px[start..i] {
            out.extend_from_slice(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gradient(w: u16, h: u16) -> Vec<u8> {
        let mut v = Vec::new();
        for y in 0..h {
            for x in 0..w {
                // Runs and literals both.
                let c = if x < w / 2 { 10 } else { (x * 7 + y) as u8 };
                v.extend_from_slice(&[c, c.wrapping_add(1), y as u8, 200]);
            }
        }
        v
    }

    #[test]
    fn round_trips_all_depths() {
        for (ty, bits) in [
            (2, 32),
            (2, 24),
            (2, 16),
            (3, 8),
            (10, 32),
            (10, 24),
            (11, 8),
            (10, 16),
        ] {
            for desc in [0x00u8, 0x20, 0x10, 0x30] {
                let mut t = Tga::new_rgba(9, 5, gradient(9, 5), false).unwrap();
                t.image_type = ty;
                t.bits = bits;
                t.descriptor = desc | if bits == 32 { 8 } else { 0 };
                t.id = b"kotor".to_vec();
                let bytes = t.to_bytes().unwrap();
                let back = Tga::read(&bytes).unwrap();
                assert_eq!(
                    back.to_bytes().unwrap(),
                    bytes,
                    "type {ty} bits {bits} desc {desc:#x}"
                );
                if bits == 32 {
                    assert_eq!(back.pixels, t.pixels);
                }
            }
        }
    }

    #[test]
    fn orientation() {
        // 1x2 bottom-up: stored first row is the bottom.
        let mut f = vec![0u8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 0];
        f.extend_from_slice(&[0, 0, 255]); // stored row 0 = bottom = red
        f.extend_from_slice(&[255, 0, 0]); // top = blue
        f.extend_from_slice(b"TRUEVISION-XFILE.\0");
        let t = Tga::read(&f).unwrap();
        assert_eq!(&t.pixels[..4], &[0, 0, 255, 255], "top row is blue");
        assert_eq!(&t.pixels[4..], &[255, 0, 0, 255]);
        assert_eq!(t.to_bytes().unwrap(), f);
    }

    #[test]
    fn errors() {
        let mut f = vec![0u8; 18];
        f[2] = 1;
        assert!(Tga::read(&f).is_err(), "colour-mapped");
        f[2] = 2;
        f[12] = 1;
        f[14] = 1;
        f[16] = 32;
        assert!(Tga::read(&f).is_err(), "truncated pixels");
        f[16] = 12;
        assert!(Tga::read(&f).is_err(), "bad depth");
    }
}
