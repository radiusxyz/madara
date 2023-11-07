use std::collections::HashMap;
use std::fs;
use std::mem::MaybeUninit;
use std::sync::{Mutex, Once};

use config::{Config, Environment, File};
use serde::{Deserialize, Serialize};
use toml;

pub static mut CONFIG: MaybeUninit<Config> = MaybeUninit::uninit();
static INIT: Once = Once::new();

pub fn config_map() -> &'static Config {
    if INIT.is_completed() {
        unsafe { CONFIG.assume_init_ref() }
    } else {
        panic!("ConfigMap is not initialized..");
    }
}

pub fn init_config(path: &String) {
    let file_path = format!("{}/Config.toml", path);

    if let Some(parent_dir) = file_path.rfind('/') {
        if let Err(e) = fs::create_dir_all(&file_path[0..parent_dir]) {
            eprintln!("Failed to create directory: {:?}", e);
        }
    }

    if !file_exists(&file_path) {
        // Config file doesn't exist, create it with default values
        let config = DefaultConfig::default();
        save_config(&config, &file_path);
    }

    let config: Config = Config::builder()
        .add_source(File::with_name(&file_path))
        .add_source(Environment::with_prefix("da"))
        .build()
        .unwrap();

    println!("Config: {:?}", config.get_array("external_decryptor_hosts"));

    unsafe {
        INIT.call_once(|| {
            CONFIG.write(config);
        });
    }
}

#[derive(Serialize, Deserialize)]
pub struct DefaultConfig {
    sequencer_private_key: String,
    external_decryptor_hosts: Vec<String>,
    is_validating: bool,
    host: String,
    namespace: String,
    auth_token: String,
}

impl Default for DefaultConfig {
    fn default() -> Self {
        DefaultConfig {
            sequencer_private_key: "0x00c1cf1490de1352865301bb8705143f3ef938f97fdf892f1090dcb5ac7bcd1d".to_string(),
            external_decryptor_hosts: vec!["localhost:8080".to_string(), "localhost:8081".to_string()],
            is_validating: false,
            host: "".to_string(),
            namespace: "".to_string(),
            auth_token: "".to_string(),
        }
    }
}

fn save_config<T: Serialize>(config: &T, filename: &str) {
    let toml = toml::to_string_pretty(config).expect("Failed to serialize to TOML");
    fs::write(filename, toml).expect("Failed to write to Config.toml");
}

fn file_exists(filename: &str) -> bool {
    fs::metadata(filename).is_ok()
}
