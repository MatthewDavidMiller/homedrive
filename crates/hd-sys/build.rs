//! Link directives for libcrypto.
//!
//! Nothing is compiled here; the build script only tells rustc to link
//! libcrypto, and how. `HD_OPENSSL_STATIC=1` links it statically, which is
//! how the shipped binary is built so the runtime image needs no OpenSSL
//! package of its own. The static archive is looked for in
//! `HD_OPENSSL_LIB_DIR` (default `/usr/lib`, where Alpine's
//! openssl-libs-static installs it).

use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=HD_OPENSSL_STATIC");
    println!("cargo:rerun-if-env-changed=HD_OPENSSL_LIB_DIR");
    let static_link = env::var("HD_OPENSSL_STATIC").is_ok_and(|v| v == "1");
    if static_link {
        let dir = env::var("HD_OPENSSL_LIB_DIR").unwrap_or_else(|_| "/usr/lib".to_owned());
        println!("cargo:rustc-link-search=native={dir}");
    }
    let kind = if static_link { "static" } else { "dylib" };
    if env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows") {
        // A static OpenSSL for Windows needs these system libraries.
        if static_link {
            println!("cargo:rustc-link-lib=dylib=ws2_32");
            println!("cargo:rustc-link-lib=dylib=crypt32");
            println!("cargo:rustc-link-lib=dylib=advapi32");
            println!("cargo:rustc-link-lib=dylib=user32");
            println!("cargo:rustc-link-lib=dylib=gdi32");
        }
    } else {
        println!("cargo:rustc-link-lib=dylib=pthread");
    }
    if env::var_os("CARGO_FEATURE_TLS").is_some() {
        // libssl depends on libcrypto, so it comes first.
        println!("cargo:rustc-link-lib={kind}=ssl");
    }
    println!("cargo:rustc-link-lib={kind}=crypto");
}
