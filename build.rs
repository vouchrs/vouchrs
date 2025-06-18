use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=custom-ui/");
    println!("cargo:rerun-if-changed=src/static/");

    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target = env::var("TARGET").unwrap_or_else(|_| String::new());

    // Determine the correct target directory path
    let target_static_dir = if target.is_empty() {
        Path::new("target").join(&profile).join("static")
    } else {
        Path::new("target")
            .join(&target)
            .join(&profile)
            .join("static")
    };

    if fs::create_dir_all(&target_static_dir).is_ok() {
        // Copy everything from src/static/
        if let Ok(entries) = fs::read_dir("src/static") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let file_name = path.file_name().unwrap();
                    let target_path = target_static_dir.join(file_name);
                    let _ = fs::copy(&path, &target_path);
                }
            }
        }

        // Copy only .js files from custom-ui/ (overwriting any from src/static)
        if let Ok(entries) = fs::read_dir("custom-ui") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension() == Some("js".as_ref()) {
                    let file_name = path.file_name().unwrap();
                    let target_path = target_static_dir.join(file_name);
                    let _ = fs::copy(&path, &target_path);
                }
            }
        }
    }
}
