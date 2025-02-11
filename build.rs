use std::env;
use std::fs;
use std::path::{PathBuf, Path};

fn main() {
    // Build the RAPS project
    build_raps();

    // Copy the ELF file to the OUT_DIR
    copy_elf();
}

fn copy_elf() {
    // Define the source file (inside a folder, e.g., "binaries/my_binary")
    let source = "./raps/target/elf-compilation/riscv32im-succinct-zkvm-elf/release/ab-rotation-program";

    // Define the destination path (project root)
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let destination = Path::new(&out_dir).join("ab-rotation-program");

    // Copy the binary file
    fs::copy(source, &destination).expect("Failed to copy binary");
}


fn build_raps() {
    // Get the path to the nested directory relative to the root project
    let nested_dir = PathBuf::from("raps");

    // Get the current directory (where build.rs is located)
    let current_dir = env::current_dir().expect("Failed to get current directory");

    // Combine paths to get the full path to the nested directory
    let full_nested_path = current_dir.join(&nested_dir);

    // Print directory for debugging
    println!("cargo:warning=Building in directory: {}", full_nested_path.display());

    // Run cargo build in the nested directory
    let status = std::process::Command::new("cargo")
        .current_dir(&full_nested_path)
        .arg("build")
        .arg("--release")
        .status()
        .expect("Failed to execute cargo build");

    if !status.success() {
        panic!("Failed to build nested project");
    }

    // Tell cargo to rerun this build script if files in the nested directory change
    println!("cargo:rerun-if-changed={}", nested_dir.display());
}