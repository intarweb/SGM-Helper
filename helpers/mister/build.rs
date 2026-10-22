use std::process::Command;

/// The build's own identity, so a state marker can tell one build from another.
///
/// The package version is the same for every fork build (0.4.16), so a marker
/// stamped with it never expires when the binary is replaced by a fixed one.
/// A release workflow can set SGM_BUILD_ID; otherwise the commit is used.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-env-changed=SGM_BUILD_ID");

    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string());
    let revision = std::env::var("SGM_BUILD_ID")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            Command::new("git")
                .args(["rev-parse", "--short=12", "HEAD"])
                .output()
                .ok()
                .filter(|output| output.status.success())
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
                .filter(|value| !value.is_empty())
        });

    let identity = match revision {
        Some(revision) => format!("{version}+{revision}"),
        None => version,
    };
    println!("cargo:rustc-env=SGM_BUILD_ID={identity}");
}
