use std::process::Command;

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let boot_obj = format!("{out_dir}/boot.o");

    // NASM from PATH by default; set NASM=/path/to/nasm to use another binary.
    let nasm = std::env::var("NASM").unwrap_or_else(|_| "nasm".to_string());

    let status = Command::new(&nasm)
        .args(["-f", "elf64", "arch/x86_64/boot.s", "-o", &boot_obj])
        .status()
        .unwrap_or_else(|_| {
            panic!("Failed to run '{nasm}' — install NASM, put it on PATH or set NASM=/path/to/nasm")
        });

    assert!(status.success(), "nasm compilation failed");

    println!("cargo:rustc-link-arg={boot_obj}");
    println!("cargo:rerun-if-changed=arch/x86_64/boot.s");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-env-changed=NASM");
}
