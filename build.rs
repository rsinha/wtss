use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Define the source file (inside a folder, e.g., "binaries/my_binary")
    let source = "./raps/target/elf-compilation/riscv32im-succinct-zkvm-elf/release/ab-rotation-program";

    // Define the destination path (project root)
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let destination = Path::new(&out_dir).join("ab-rotation-program");

    // Copy the binary file
    fs::copy(source, &destination).expect("Failed to copy binary");

    // Tell Cargo to rerun if the source file changes
    println!("cargo:rerun-if-changed={}", source);
}
