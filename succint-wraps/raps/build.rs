use sp1_helper::build_program_with_args;

fn main() {
    build_program_with_args("../raps_zkvm_program", Default::default());
    build_program_with_args("../raps_compression_zkvm_program", Default::default());
}
