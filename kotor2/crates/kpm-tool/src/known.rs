//! Executable builds KPM knows, from the `game_version` tables of
//! `AddressDatabases/*.db` in the KPM submodule (`2a784bf`) and the version
//! keys its patch manifests use.

pub struct KnownBuild {
    pub sha256: &'static str,
    /// The `supported_versions` key KPM's manifests use for it.
    pub key: &'static str,
    pub description: &'static str,
}

pub const KNOWN_BUILDS: &[KnownBuild] = &[
    KnownBuild {
        sha256: "777BEE235A9E8BDD9863F6741BC3AC54BB6A113B62B1D2E4D12BBE6DB963A914",
        key: "kotor2_gog_aspyr",
        description: "KotOR 2, GOG, Aspyr update, Windows swkotor2.exe",
    },
    KnownBuild {
        sha256: "6A522E71631DCEE93467BD2010F3B23D9145326E1E2E89305F13AB104DBBFFEF",
        key: "kotor2_steam_aspyr",
        description: "KotOR 2, Steam, Aspyr update, Windows swkotor2.exe",
    },
    KnownBuild {
        sha256: "ED043D21A4578FD1C6F1557F0F72BDE5589BA3572A5B6F1A687ED9FEEAB49AC3",
        key: "kotor2_steam_aspyr_linux",
        description: "KotOR 2, Steam, Aspyr native Linux build (ELF, build-id b0ac5acb)",
    },
    KnownBuild {
        sha256: "1C536C3EF2E8BED348B38934B381E3DC427F3EBEE21FADDFBD7524FBB2388D77",
        key: "kotor2_steam_aspyr_macos",
        description: "KotOR 2 1.0.2, Steam, Aspyr macOS build (x86_64 Mach-O)",
    },
    KnownBuild {
        sha256: "9C10E0450A6EECA417E036E3CDE7474FED1F0A92AAB018446D156944DEA91435",
        key: "kotor1_gog_103",
        description: "KotOR 1 1.03, GOG, Windows swkotor.exe",
    },
    KnownBuild {
        sha256: "34E6D971C034222A417995D8E1E8FDD9F8781795C9C289BD86C499A439F34C88",
        key: "kotor1_steam_103",
        description: "KotOR 1 1.03, Steam, Windows swkotor.exe (SteamStub)",
    },
    KnownBuild {
        sha256: "761F9466F456A83909036BAEBB5C43167D722387BE66E54617BA20A8C49E9886",
        key: "kotor1_cdcrack_103",
        description: "KotOR 1 1.03, 'CD crack' build (GOG's with a 16-byte watermark)",
    },
    KnownBuild {
        sha256: "C1FCB8D37C702849882A17751C63EE0AF7C2B9CBBC3B31B98A5F0EDBC27C6D71",
        key: "kotor1_steam_aspyr_macos",
        description: "KotOR 1, Steam, Aspyr macOS build",
    },
];

pub fn lookup(sha256: &str) -> Option<&'static KnownBuild> {
    KNOWN_BUILDS
        .iter()
        .find(|b| b.sha256.eq_ignore_ascii_case(sha256))
}
