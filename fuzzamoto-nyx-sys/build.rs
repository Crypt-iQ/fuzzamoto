use std::{path::PathBuf, process::Command};

// Get the afl coverage map size of the given binary
fn get_map_size(binary: &PathBuf) -> Option<String> {
    let output = String::from_utf8_lossy(
        &Command::new(binary)
            .env("AFL_DUMP_MAP_SIZE", "1")
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute {:?}", binary.display()))
            .stdout,
    )
    .trim()
    .to_string();

    (!output.is_empty()).then_some(output)
}

fn main() {
    let mut build = cc::Build::new();
    build.file("src/nyx-agent.c").define("NO_PT_NYX", None);

    let _ = std::env::var("BITCOIND_PATH").map(|path| {
        if let Some(size) = get_map_size(&path.into()) {
            build.define("TARGET_MAP_SIZE", &*size);
        }
    });

    build.compile("nyx_agent");

    println!("cargo:rerun-if-changed=src/nyx-agent.c");
    println!("cargo:rerun-if-env-changed=BITCOIND_PATH");
}
