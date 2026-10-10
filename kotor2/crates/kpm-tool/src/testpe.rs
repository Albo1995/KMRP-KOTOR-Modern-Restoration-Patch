//! A builder for small synthetic PE32 images, so the tests never need a game
//! file: headers, a section table, raw section data, and optionally an export
//! table.

const FILE_ALIGN: u32 = 0x200;
const SECTION_ALIGN: u32 = 0x1000;
const HEADERS_SIZE: u32 = 0x400;
/// e_lfanew; goblin wants room for a DOS stub after the 64-byte header.
const PE_OFFSET: usize = 0x80;

pub const TEXT: u32 = 0x6000_0020; // code | execute | read
pub const RDATA: u32 = 0x4000_0040; // initialised data | read
pub const DATA: u32 = 0xC000_0040; // initialised data | read | write

#[derive(Debug, Clone)]
pub struct SectionSpec {
    pub name: String,
    pub data: Vec<u8>,
    /// 0 means "the raw size".
    pub virtual_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone)]
pub struct PeBuilder {
    pub image_base: u32,
    pub dll: bool,
    pub machine: u16,
    pub sections: Vec<SectionSpec>,
    pub exports: Vec<String>,
}

impl Default for PeBuilder {
    fn default() -> Self {
        PeBuilder {
            image_base: 0x0040_0000,
            dll: false,
            machine: 0x014C,
            sections: Vec::new(),
            exports: Vec::new(),
        }
    }
}

fn align(v: u32, a: u32) -> u32 {
    v.div_ceil(a) * a
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

impl PeBuilder {
    pub fn new() -> PeBuilder {
        PeBuilder::default()
    }

    pub fn section(mut self, name: &str, data: Vec<u8>, characteristics: u32) -> PeBuilder {
        self.sections.push(SectionSpec {
            name: name.to_string(),
            data,
            virtual_size: 0,
            characteristics,
        });
        self
    }

    /// A section whose virtual size exceeds its raw data (a zero-filled tail).
    pub fn section_with_vsize(
        mut self,
        name: &str,
        data: Vec<u8>,
        virtual_size: u32,
        characteristics: u32,
    ) -> PeBuilder {
        self.sections.push(SectionSpec {
            name: name.to_string(),
            data,
            virtual_size,
            characteristics,
        });
        self
    }

    pub fn dll(mut self, exports: &[&str]) -> PeBuilder {
        self.dll = true;
        self.exports = exports.iter().map(|s| s.to_string()).collect();
        self
    }

    /// RVA each section will get (sections are laid out in order, 0x1000 apart).
    pub fn rva_of(&self, index: usize) -> u32 {
        let mut rva = SECTION_ALIGN;
        for s in &self.sections[..index] {
            let span = s.virtual_size.max(s.data.len() as u32).max(1);
            rva += align(span, SECTION_ALIGN);
        }
        rva
    }

    /// VA of byte `offset` of section `index`.
    pub fn va(&self, index: usize, offset: u32) -> u64 {
        self.image_base as u64 + self.rva_of(index) as u64 + offset as u64
    }

    fn export_section(&self, rva: u32, first_code_rva: u32) -> Vec<u8> {
        let mut names = self.exports.clone();
        names.sort();
        let n = names.len() as u32;
        let dir = 40u32;
        let funcs = dir;
        let name_ptrs = funcs + 4 * n;
        let ordinals = name_ptrs + 4 * n;
        let mut strings = ordinals + 2 * n;
        let mut out = vec![0u8; strings as usize];
        let dll_name = b"synthetic.dll\0";
        let dll_name_rva = rva + strings;
        out.extend_from_slice(dll_name);
        strings += dll_name.len() as u32;
        put32(&mut out, 12, dll_name_rva);
        put32(&mut out, 16, 1); // ordinal base
        put32(&mut out, 20, n);
        put32(&mut out, 24, n);
        put32(&mut out, 28, rva + funcs);
        put32(&mut out, 32, rva + name_ptrs);
        put32(&mut out, 36, rva + ordinals);
        for (i, name) in names.iter().enumerate() {
            let i = i as u32;
            put32(&mut out, (funcs + 4 * i) as usize, first_code_rva + i * 16);
            put32(&mut out, (name_ptrs + 4 * i) as usize, rva + strings);
            put16(&mut out, (ordinals + 2 * i) as usize, i as u16);
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            strings += name.len() as u32 + 1;
        }
        out
    }

    pub fn build(&self) -> Vec<u8> {
        let mut sections = self.sections.clone();
        let mut export_dir = None;
        if !self.exports.is_empty() {
            let index = sections.len();
            let rva = {
                let probe = PeBuilder {
                    sections: sections.clone(),
                    ..self.clone()
                };
                if index == 0 {
                    SECTION_ALIGN
                } else {
                    probe.rva_of(index)
                }
            };
            let code_rva = if sections.is_empty() {
                rva
            } else {
                SECTION_ALIGN
            };
            let data = self.export_section(rva, code_rva);
            export_dir = Some((rva, data.len() as u32));
            sections.push(SectionSpec {
                name: ".edata".into(),
                data,
                virtual_size: 0,
                characteristics: RDATA,
            });
        }
        let layout = PeBuilder {
            sections: sections.clone(),
            ..self.clone()
        };

        let nsec = sections.len();
        assert!(PE_OFFSET + 4 + 20 + 224 + 40 * nsec <= HEADERS_SIZE as usize);
        let mut raw_offsets = Vec::new();
        let mut file_len = HEADERS_SIZE;
        for s in &sections {
            raw_offsets.push(file_len);
            file_len += align(s.data.len() as u32, FILE_ALIGN);
        }
        let last = nsec.saturating_sub(1);
        let size_of_image = if nsec == 0 {
            SECTION_ALIGN
        } else {
            let s = &sections[last];
            layout.rva_of(last)
                + align(
                    s.virtual_size.max(s.data.len() as u32).max(1),
                    SECTION_ALIGN,
                )
        };

        let mut b = vec![0u8; file_len as usize];
        b[0..2].copy_from_slice(b"MZ");
        put32(&mut b, 0x3C, PE_OFFSET as u32);
        b[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
        let coff = PE_OFFSET + 4;
        put16(&mut b, coff, self.machine);
        put16(&mut b, coff + 2, nsec as u16);
        put16(&mut b, coff + 16, 224);
        put16(
            &mut b,
            coff + 18,
            0x0102 | if self.dll { 0x2000 } else { 0 },
        );
        let opt = coff + 20;
        put16(&mut b, opt, 0x010B);
        put32(&mut b, opt + 16, 0); // entry point
        put32(&mut b, opt + 20, SECTION_ALIGN); // base of code
        put32(&mut b, opt + 28, self.image_base);
        put32(&mut b, opt + 32, SECTION_ALIGN);
        put32(&mut b, opt + 36, FILE_ALIGN);
        put16(&mut b, opt + 40, 4); // OS major
        put16(&mut b, opt + 48, 4); // subsystem major
        put32(&mut b, opt + 56, size_of_image);
        put32(&mut b, opt + 60, HEADERS_SIZE);
        put16(&mut b, opt + 68, 2); // GUI
        put32(&mut b, opt + 72, 0x10_0000);
        put32(&mut b, opt + 76, 0x1000);
        put32(&mut b, opt + 80, 0x10_0000);
        put32(&mut b, opt + 84, 0x1000);
        put32(&mut b, opt + 92, 16); // NumberOfRvaAndSizes
        if let Some((rva, size)) = export_dir {
            put32(&mut b, opt + 96, rva);
            put32(&mut b, opt + 100, size);
        }
        let mut sh = opt + 224;
        for (i, s) in sections.iter().enumerate() {
            let mut name = [0u8; 8];
            let n = s.name.len().min(8);
            name[..n].copy_from_slice(&s.name.as_bytes()[..n]);
            b[sh..sh + 8].copy_from_slice(&name);
            let vsize = if s.virtual_size == 0 {
                s.data.len() as u32
            } else {
                s.virtual_size
            };
            put32(&mut b, sh + 8, vsize);
            put32(&mut b, sh + 12, layout.rva_of(i));
            put32(&mut b, sh + 16, align(s.data.len() as u32, FILE_ALIGN));
            put32(&mut b, sh + 20, raw_offsets[i]);
            put32(&mut b, sh + 36, s.characteristics);
            let at = raw_offsets[i] as usize;
            b[at..at + s.data.len()].copy_from_slice(&s.data);
            sh += 40;
        }
        b
    }
}
