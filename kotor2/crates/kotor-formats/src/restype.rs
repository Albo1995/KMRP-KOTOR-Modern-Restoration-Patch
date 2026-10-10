//! Odyssey resource type ids and their file extensions.
//!
//! The numbers are the ones KEY, BIF, ERF and RIM files store. The table is
//! taken from public documentation (xoreos `src/aurora/types.h`, PyKotor's
//! `ResourceType`), not measured from the game; ids KotOR does not use are
//! included where they are well known so that listings of foreign archives
//! still read sensibly.

use std::fmt;

/// A resource type id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ResType(pub u16);

macro_rules! restypes {
    ($($name:ident = $id:literal, $ext:literal;)*) => {
        impl ResType {
            $(
                #[doc = concat!("`.", $ext, "`")]
                pub const $name: ResType = ResType($id);
            )*
        }
        const TABLE: &[(u16, &str)] = &[$(($id, $ext)),*];
    };
}

restypes! {
    RES = 0, "res";
    BMP = 1, "bmp";
    MVE = 2, "mve";
    TGA = 3, "tga";
    WAV = 4, "wav";
    PLT = 6, "plt";
    INI = 7, "ini";
    MP3 = 8, "mp3";
    MPG = 9, "mpg";
    TXT = 10, "txt";
    WMA = 11, "wma";
    WMV = 12, "wmv";
    XMV = 13, "xmv";
    PLH = 2000, "plh";
    TEX = 2001, "tex";
    MDL = 2002, "mdl";
    THG = 2003, "thg";
    FNT = 2005, "fnt";
    LUA = 2007, "lua";
    SLT = 2008, "slt";
    NSS = 2009, "nss";
    NCS = 2010, "ncs";
    MOD = 2011, "mod";
    ARE = 2012, "are";
    SET = 2013, "set";
    IFO = 2014, "ifo";
    BIC = 2015, "bic";
    WOK = 2016, "wok";
    TWODA = 2017, "2da";
    TLK = 2018, "tlk";
    TXI = 2022, "txi";
    GIT = 2023, "git";
    BTI = 2024, "bti";
    UTI = 2025, "uti";
    BTC = 2026, "btc";
    UTC = 2027, "utc";
    DLG = 2029, "dlg";
    ITP = 2030, "itp";
    BTT = 2031, "btt";
    UTT = 2032, "utt";
    DDS = 2033, "dds";
    BTS = 2034, "bts";
    UTS = 2035, "uts";
    LTR = 2036, "ltr";
    GFF = 2037, "gff";
    FAC = 2038, "fac";
    BTE = 2039, "bte";
    UTE = 2040, "ute";
    BTD = 2041, "btd";
    UTD = 2042, "utd";
    BTP = 2043, "btp";
    UTP = 2044, "utp";
    DFT = 2045, "dft";
    GIC = 2046, "gic";
    GUI = 2047, "gui";
    CSS = 2048, "css";
    CCS = 2049, "ccs";
    BTM = 2050, "btm";
    UTM = 2051, "utm";
    DWK = 2052, "dwk";
    PWK = 2053, "pwk";
    BTG = 2054, "btg";
    UTG = 2055, "utg";
    JRL = 2056, "jrl";
    SAV = 2057, "sav";
    UTW = 2058, "utw";
    FOURPC = 2059, "4pc";
    SSF = 2060, "ssf";
    HAK = 2061, "hak";
    NWM = 2062, "nwm";
    BIK = 2063, "bik";
    NDB = 2064, "ndb";
    PTM = 2065, "ptm";
    PTT = 2066, "ptt";
    LYT = 3000, "lyt";
    VIS = 3001, "vis";
    RIM = 3002, "rim";
    PTH = 3003, "pth";
    LIP = 3004, "lip";
    BWM = 3005, "bwm";
    TXB = 3006, "txb";
    TPC = 3007, "tpc";
    MDX = 3008, "mdx";
    RSV = 3009, "rsv";
    SIG = 3010, "sig";
    MAB = 3011, "mab";
    ERF = 9997, "erf";
    BIF = 9998, "bif";
    KEY = 9999, "key";
}

impl ResType {
    /// The lowercase extension, if the id is known.
    pub fn extension(self) -> Option<&'static str> {
        TABLE.iter().find(|(id, _)| *id == self.0).map(|(_, e)| *e)
    }

    /// Look an extension up (case-insensitive, leading dot allowed). Also
    /// accepts a bare number or `typeNNNN`, the form [`Display`] prints for
    /// unknown ids.
    ///
    /// [`Display`]: fmt::Display
    pub fn from_extension(ext: &str) -> Option<ResType> {
        let ext = ext.strip_prefix('.').unwrap_or(ext);
        if let Some((id, _)) = TABLE.iter().find(|(_, e)| e.eq_ignore_ascii_case(ext)) {
            return Some(ResType(*id));
        }
        let digits = ext
            .strip_prefix("type")
            .or_else(|| ext.strip_prefix("TYPE"))
            .unwrap_or(ext);
        digits.parse::<u16>().ok().map(ResType)
    }

    /// Every id this table knows, with its extension.
    pub fn known() -> impl Iterator<Item = (ResType, &'static str)> {
        TABLE.iter().map(|&(id, e)| (ResType(id), e))
    }

    /// True for the GFF-based types (`.gui`, `.utc`, `.dlg`, ...).
    pub fn is_gff(self) -> bool {
        matches!(
            self.0,
            2012 | 2014 | 2015 | 2023..=2032 | 2034..=2035 | 2037..=2044 | 2046..=2047 | 2050..=2051 | 2054..=2056 | 2058 | 2065..=2066
        )
    }
}

impl fmt::Display for ResType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.extension() {
            Some(e) => f.write_str(e),
            None => write!(f, "type{}", self.0),
        }
    }
}

/// Split `"resref.ext"` into its resref and type.
pub fn parse_resource_name(name: &str) -> Option<(String, ResType)> {
    let (stem, ext) = name.rsplit_once('.')?;
    if stem.is_empty() {
        return None;
    }
    Some((stem.to_string(), ResType::from_extension(ext)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups() {
        assert_eq!(ResType::from_extension("GUI"), Some(ResType::GUI));
        assert_eq!(ResType::from_extension(".2da"), Some(ResType(2017)));
        assert_eq!(ResType(3007).to_string(), "tpc");
        assert_eq!(ResType(4242).to_string(), "type4242");
        assert_eq!(ResType::from_extension("type4242"), Some(ResType(4242)));
        assert_eq!(
            parse_resource_name("mainmenu.gui"),
            Some(("mainmenu".into(), ResType::GUI))
        );
        assert!(ResType::GUI.is_gff());
        assert!(ResType::DLG.is_gff());
        assert!(!ResType::TPC.is_gff());
        let mut ids: Vec<u16> = TABLE.iter().map(|t| t.0).collect();
        ids.dedup();
        assert_eq!(ids.len(), TABLE.len(), "duplicate ids");
    }
}
