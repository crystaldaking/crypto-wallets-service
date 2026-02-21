fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile protobuf definitions
    // Requires protoc to be installed system-wide (apt install protobuf-compiler)
    // protoc_bin_vendored removed to avoid unsafe { std::env::set_var } in Rust 2024
    tonic_build::configure()
        .build_server(true)
        .compile_protos(&["proto/wallet.proto"], &["proto"])?;
    Ok(())
}
