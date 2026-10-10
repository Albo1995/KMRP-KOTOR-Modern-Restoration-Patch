//! The parts of a PE image the verifier needs: image base, section table,
//! export names, and VA <-> file-offset mapping.

use anyhow::{bail, Context, Result};

pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
pub const IMAGE_FILE_DLL: u16 = 0x2000;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    /// RVA of the section start.
    pub rva: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl Section {
    /// Bytes of address space the section spans (some linkers leave
    /// VirtualSize 0, meaning "SizeOfRawData").
    pub fn span(&self) -> u32 {
        if self.virtual_size == 0 {
            self.raw_size
        } else {
            self.virtual_size
        }
    }

    /// Bytes at the start of the section that come from the file.
    pub fn file_backed(&self) -> u32 {
        self.raw_size.min(self.span())
    }

    pub fn is_executable(&self) -> bool {
        self.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) != 0
    }
}

#[derive(Debug, Clone)]
pub struct Image {
    pub data: Vec<u8>,
    pub machine: u16,
    pub characteristics: u16,
    pub is_pe32_plus: bool,
    pub image_base: u64,
    pub size_of_headers: u32,
    pub sections: Vec<Section>,
    pub exports: Vec<String>,
}

/// Where a VA range lives in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapped {
    pub offset: usize,
    /// Index into `Image::sections`, or `None` for the headers.
    pub section: Option<usize>,
}

impl Image {
    pub fn parse(data: Vec<u8>) -> Result<Image> {
        let pe = goblin::pe::PE::parse(&data).context("not a parseable PE image")?;
        let header = &pe.header;
        let optional = header
            .optional_header
            .context("PE image has no optional header")?;
        let sections = pe
            .sections
            .iter()
            .map(|s| Section {
                name: String::from_utf8_lossy(&s.name)
                    .trim_end_matches('\0')
                    .to_string(),
                rva: s.virtual_address,
                virtual_size: s.virtual_size,
                raw_offset: s.pointer_to_raw_data,
                raw_size: s.size_of_raw_data,
                characteristics: s.characteristics,
            })
            .collect();
        let exports = pe
            .exports
            .iter()
            .filter_map(|e| e.name.map(str::to_string))
            .collect();
        let image = Image {
            machine: header.coff_header.machine,
            characteristics: header.coff_header.characteristics,
            is_pe32_plus: pe.is_64,
            image_base: pe.image_base as u64,
            size_of_headers: optional.windows_fields.size_of_headers,
            sections,
            exports,
            data,
        };
        Ok(image)
    }

    pub fn is_i386(&self) -> bool {
        self.machine == IMAGE_FILE_MACHINE_I386 && !self.is_pe32_plus
    }

    pub fn is_dll(&self) -> bool {
        self.characteristics & IMAGE_FILE_DLL != 0
    }

    /// SteamStub leaves a `.bind` section; its `.text` is encrypted on disk
    /// (KPatchCore's `PeExecutableImage.IsPacked`).
    pub fn is_steamstub_packed(&self) -> bool {
        self.sections.iter().any(|s| s.name == ".bind")
    }

    pub fn section_of_va(&self, va: u64) -> Option<usize> {
        let rva = va.checked_sub(self.image_base)?;
        self.sections
            .iter()
            .position(|s| rva >= s.rva as u64 && rva < s.rva as u64 + s.span() as u64)
    }

    /// Map `[va, va+len)` to file offsets. It must lie wholly in the headers
    /// or wholly in one section's file-backed bytes.
    pub fn map(&self, va: u64, len: usize) -> Result<Mapped> {
        let len = len as u64;
        let Some(rva) = va.checked_sub(self.image_base) else {
            bail!(
                "{va:#010X} is below the image base {:#010X}",
                self.image_base
            );
        };
        let end = rva + len;
        if rva < self.size_of_headers as u64 {
            if end > self.size_of_headers as u64 {
                bail!("{va:#010X}+{len} runs past the end of the PE headers");
            }
            return self.checked(rva as usize, len as usize, None);
        }
        let Some(index) = self.section_of_va(va) else {
            bail!("{va:#010X} (RVA {rva:#X}) is not inside any section of this image");
        };
        let s = &self.sections[index];
        let delta = rva - s.rva as u64;
        if end > s.rva as u64 + s.span() as u64 {
            bail!(
                "{va:#010X}+{len} runs past the end of section {} (ends at {:#010X})",
                s.name,
                self.image_base + s.rva as u64 + s.span() as u64
            );
        }
        if delta + len > s.file_backed() as u64 {
            bail!(
                "{va:#010X}+{len} is in the zero-filled tail of {}, which the file does not hold",
                s.name
            );
        }
        self.checked(
            (s.raw_offset as u64 + delta) as usize,
            len as usize,
            Some(index),
        )
    }

    fn checked(&self, offset: usize, len: usize, section: Option<usize>) -> Result<Mapped> {
        if offset.checked_add(len).is_none_or(|e| e > self.data.len()) {
            bail!("file offset {offset:#X}+{len} is past the end of the file (truncated image?)");
        }
        Ok(Mapped { offset, section })
    }

    /// Bytes at `[va, va+len)`.
    pub fn read_va(&self, va: u64, len: usize) -> Result<&[u8]> {
        let m = self.map(va, len)?;
        Ok(&self.data[m.offset..m.offset + len])
    }

    /// Up to `max` file-backed bytes from `va` to the end of its section.
    pub fn read_va_upto(&self, va: u64, max: usize) -> Result<&[u8]> {
        let m = self.map(va, 1)?;
        let limit = match m.section {
            Some(i) => {
                let s = &self.sections[i];
                let rva = va - self.image_base;
                (s.file_backed() as u64 - (rva - s.rva as u64)) as usize
            }
            None => self.size_of_headers as usize - (va - self.image_base) as usize,
        };
        let n = max.min(limit).min(self.data.len() - m.offset);
        Ok(&self.data[m.offset..m.offset + n])
    }

    /// The VA a file offset is loaded at, if it is in the headers or a
    /// section's file-backed bytes.
    pub fn offset_to_va(&self, offset: usize) -> Option<(u64, Option<usize>)> {
        if offset < self.size_of_headers as usize {
            return Some((self.image_base + offset as u64, None));
        }
        self.sections.iter().enumerate().find_map(|(i, s)| {
            let start = s.raw_offset as usize;
            let end = start + s.file_backed() as usize;
            (offset >= start && offset < end).then(|| {
                (
                    self.image_base + s.rva as u64 + (offset - start) as u64,
                    Some(i),
                )
            })
        })
    }

    pub fn section_name(&self, index: Option<usize>) -> &str {
        match index {
            Some(i) => &self.sections[i].name,
            None => "(headers)",
        }
    }

    pub fn summary(&self) -> String {
        let kind = if self.is_pe32_plus { "PE32+" } else { "PE32" };
        let machine = if self.machine == IMAGE_FILE_MACHINE_I386 {
            "i386".to_string()
        } else {
            format!("machine {:#06X}", self.machine)
        };
        let names: Vec<_> = self.sections.iter().map(|s| s.name.as_str()).collect();
        format!(
            "{kind} {machine}{}, image base {:#010X}, {} sections ({})",
            if self.is_dll() { " DLL" } else { "" },
            self.image_base,
            self.sections.len(),
            names.join(" ")
        )
    }
}
