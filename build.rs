use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=src/static/");

    // Copy files to target/{profile}/static for runtime access
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target_static_dir = Path::new("target").join(&profile).join("static");

    if fs::create_dir_all(&target_static_dir).is_ok() {
        // Copy files from src/static/ to target/{profile}/static/
        if let Ok(entries) = fs::read_dir("src/static") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let file_name = path.file_name().unwrap();
                    let target_path = target_static_dir.join(file_name);
                    if fs::copy(&path, &target_path).is_ok() {
                        println!("Copied {} to target static", path.display());
                    }
                }
            }
        }
    }
}
