//! Link-time configuration for the optional SYN sweep.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // `wpcap.lib` is an import library, so linking it makes `wpcap.dll` a
    // load-time dependency of the engine. On a machine without Npcap the
    // process then cannot start at all - and this one binary carries connect
    // scanning and UDP too, so a driver that only the sweep needs took away
    // every scan mode that never needed it. The failure is also mute: the
    // launcher sees a missing DLL, not a message it can pass on.
    //
    // Delay-loading moves that resolution to the first call into wpcap, which
    // is the only place that needs the driver. A build without the feature
    // never links wpcap at all, so this is the feature's own concern.
    //
    // The engine checks the driver is loadable before it calls pcap: an
    // unresolved delay-load raises a Win32 exception rather than returning,
    // which would end the process as abruptly as the load-time failure did.
    let syn_sweep = std::env::var_os("CARGO_FEATURE_SYN_SWEEP").is_some();
    let windows_msvc = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if syn_sweep && windows_msvc {
        // The shipped binary only. Applied to every target, the flag also
        // reaches the integration test, which spawns the engine rather than
        // calling wpcap itself - and the linker warns about a delay-load for a
        // library nothing imports.
        println!("cargo:rustc-link-arg-bins=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-arg-bins=delayimp.lib");
    }
}
