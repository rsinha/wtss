use std::env;
use std::fs;
use std::path::{PathBuf, Path};

fn main() {
    // Build the RAPS project
    build_wraps();

    // Copy the ELF file to the OUT_DIR
    copy_elf();
}

fn copy_elf() {
    // Define the destination path (project root)
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");

    let source = "./succint-wraps/target/elf-compilation/riscv32im-succinct-zkvm-elf/release/ab-rotation-program";
    let destination = Path::new(&out_dir).join("ab-rotation-program");
    fs::copy(source, &destination).expect("Failed to copy binary");

    let source = "./succint-wraps/target/elf-compilation/riscv32im-succinct-zkvm-elf/release/raps-compression-program";
    let destination = Path::new(&out_dir).join("raps-compression-program");
    fs::copy(source, &destination).expect("Failed to copy binary");
}


fn build_wraps() {
    // Get the path to the nested directory relative to the root project
    let nested_dir = PathBuf::from("succint-wraps");

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
