// `DllMain` is stdcall, so its object symbol is `_DllMain@12`, while rustc's
// export list names it `DllMain`. GNU ld matches the two up either way, but
// warns ("resolving _DllMain by linking to _DllMain@12") unless told the
// fixup is intended. The export it produces is the plain name either way.
fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if target == "i686-pc-windows-gnu" {
        println!("cargo:rustc-link-arg-cdylib=-Wl,--enable-stdcall-fixup");
    }
}
