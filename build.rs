use std::process::Command;

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let boot_obj = format!("{out_dir}/boot.o");

    // Compile arch/x86_64/boot.s → boot.o
    let status = Command::new("nasm")
        .args(["-f", "elf64", "arch/x86_64/boot.s", "-o", &boot_obj])
        .status()
        .expect("Failed to run nasm — is it installed?");

    assert!(status.success(), "nasm compilation of arch/x86_64/boot.s failed");

    // Pass boot.o to the linker (must come before Rust objects)
    println!("cargo:rustc-link-arg={boot_obj}");

    // Rerun build script if these files change
    println!("cargo:rerun-if-changed=arch/x86_64/boot.s");
    println!("cargo:rerun-if-changed=linker.ld");
}
