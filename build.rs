use std::process::Command;

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let boot_obj = format!("{out_dir}/boot.o");

    // On Windows, nasm may be installed to a specific path
    let nasm = if cfg!(target_os = "windows") {
        // Try PATH first, then common Windows install location
        which("nasm").unwrap_or_else(|| {
            r"C:\Program Files\NASM\nasm.exe".to_string()
        })
    } else {
        "nasm".to_string()
    };

    let status = Command::new(&nasm)
        .args(["-f", "elf64", "arch/x86_64/boot.s", "-o", &boot_obj])
        .status()
        .unwrap_or_else(|_| panic!("Failed to run nasm at '{nasm}' — is NASM installed?"));

    assert!(status.success(), "nasm compilation failed");

    println!("cargo:rustc-link-arg={boot_obj}");
    println!("cargo:rerun-if-changed=arch/x86_64/boot.s");
    println!("cargo:rerun-if-changed=linker.ld");
}

fn which(cmd: &str) -> Option<String> {
    let output = Command::new("where").arg(cmd).output().ok()?;
    if output.status.success() {
        let path = String::from_utf8(output.stdout).ok()?;
        Some(path.lines().next()?.trim().to_string())
    } else {
        None
    }
}
