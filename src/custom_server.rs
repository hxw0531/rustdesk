use hbb_common::{
    bail,
    base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _},
    config::{keys::OPTION_HIDE_SERVER_SETTINGS, BUILTIN_SETTINGS},
    log,
    sodiumoxide::crypto::{secretbox, sign},
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

/// Flag to track if config was loaded from file (to hide server settings in UI)
static CONFIG_LOADED_FROM_FILE: AtomicBool = AtomicBool::new(false);

/// Check if custom server config was loaded from a config file
pub fn is_config_loaded_from_file() -> bool {
    CONFIG_LOADED_FROM_FILE.load(Ordering::Relaxed)
}

/// Hide server settings in UI when config is loaded from file
fn set_hide_server_settings() {
    BUILTIN_SETTINGS
        .write()
        .unwrap()
        .insert(OPTION_HIDE_SERVER_SETTINGS.to_string(), "Y".to_string());
    CONFIG_LOADED_FROM_FILE.store(true, Ordering::Relaxed);
    log::info!("Server settings hidden in UI (config loaded from file)");
}

const CONFIG_FILE_NAME: &str = "custom_server.json";
const ENCRYPTED_CONFIG_FILE_NAME: &str = "custom_server.enc";

// Encryption key for custom server config
// Can be customized at compile time via environment variable:
//   CUSTOM_SERVER_ENCRYPTION_KEY="YourCustom32ByteKeyHere12345678"
// Must be exactly 32 bytes (characters)
const ENCRYPTION_SEED: &[u8; 32] = match option_env!("CUSTOM_SERVER_ENCRYPTION_KEY") {
    Some(key) => {
        // At compile time, convert the env var to a fixed-size array
        // This will fail at compile time if the key is not exactly 32 bytes
        const fn to_array(s: &str) -> [u8; 32] {
            let bytes = s.as_bytes();
            assert!(bytes.len() == 32, "CUSTOM_SERVER_ENCRYPTION_KEY must be exactly 32 bytes");
            let mut arr = [0u8; 32];
            let mut i = 0;
            while i < 32 {
                arr[i] = bytes[i];
                i += 1;
            }
            arr
        }
        &to_array(key)
    }
    None => b"RustDesk_CustomServer_Config_Key", // Default key
};

#[derive(Debug, PartialEq, Default, Serialize, Deserialize, Clone)]
pub struct CustomServer {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub api: String,
    #[serde(default)]
    pub relay: String,
}

fn get_custom_server_from_config_string(s: &str) -> ResultType<CustomServer> {
    let tmp: String = s.chars().rev().collect();
    const PK: &[u8; 32] = &[
        88, 168, 68, 104, 60, 5, 163, 198, 165, 38, 12, 85, 114, 203, 96, 163, 70, 48, 0, 131, 57,
        12, 46, 129, 83, 17, 84, 193, 119, 197, 130, 103,
    ];
    let pk = sign::PublicKey(*PK);
    let data = URL_SAFE_NO_PAD.decode(tmp)?;
    if let Ok(lic) = serde_json::from_slice::<CustomServer>(&data) {
        return Ok(lic);
    }
    if let Ok(data) = sign::verify(&data, &pk) {
        Ok(serde_json::from_slice::<CustomServer>(&data)?)
    } else {
        bail!("sign:verify failed");
    }
}

/// Encrypt custom server config to bytes
pub fn encrypt_config(server: &CustomServer) -> ResultType<Vec<u8>> {
    let json = serde_json::to_string(server)?;
    let key = secretbox::Key(*ENCRYPTION_SEED);
    let nonce = secretbox::Nonce([0u8; secretbox::NONCEBYTES]);
    let encrypted = secretbox::seal(json.as_bytes(), &nonce, &key);
    Ok(encrypted)
}

/// Decrypt custom server config from bytes
fn decrypt_config(data: &[u8]) -> ResultType<CustomServer> {
    let key = secretbox::Key(*ENCRYPTION_SEED);
    let nonce = secretbox::Nonce([0u8; secretbox::NONCEBYTES]);
    let decrypted = secretbox::open(data, &nonce, &key)
        .map_err(|_| hbb_common::anyhow::anyhow!("Failed to decrypt config"))?;
    let json = String::from_utf8(decrypted)?;
    let server: CustomServer = serde_json::from_str(&json)?;
    Ok(server)
}

/// Generate encrypted config file content (base64 encoded for easy handling)
pub fn generate_encrypted_config(server: &CustomServer) -> ResultType<String> {
    let encrypted = encrypt_config(server)?;
    #[allow(deprecated)]
    Ok(hbb_common::base64::encode(&encrypted))
}

/// Parse encrypted config from base64 string
fn parse_encrypted_config(content: &str) -> ResultType<CustomServer> {
    #[allow(deprecated)]
    let data = hbb_common::base64::decode(content.trim())
        .map_err(|_| hbb_common::anyhow::anyhow!("Invalid base64 encoding"))?;
    decrypt_config(&data)
}

/// Find config file path, checking multiple locations:
/// 1. Encrypted config file (custom_server.enc) - higher priority
/// 2. Plain JSON config file (custom_server.json)
/// Searches in: current exe directory, then portable exe directory
fn find_config_file_path() -> Option<(PathBuf, bool)> {
    let dirs_to_check: Vec<PathBuf> = {
        let mut dirs = Vec::new();
        
        // Current exe directory
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                dirs.push(exe_dir.to_path_buf());
            }
        }
        
        // Portable exe directory
        if let Ok(portable_exe) = std::env::var("RUSTDESK_APPNAME") {
            let portable_path = PathBuf::from(&portable_exe);
            if let Some(portable_dir) = portable_path.parent() {
                dirs.push(portable_dir.to_path_buf());
            }
        }
        
        dirs
    };

    // Check each directory for encrypted config first, then plain config
    for dir in &dirs_to_check {
        // Check encrypted config first (higher priority)
        let enc_path = dir.join(ENCRYPTED_CONFIG_FILE_NAME);
        log::debug!("Checking encrypted config at: {:?}", enc_path);
        if enc_path.exists() {
            return Some((enc_path, true));
        }
        
        // Then check plain JSON config
        let json_path = dir.join(CONFIG_FILE_NAME);
        log::debug!("Checking plain config at: {:?}", json_path);
        if json_path.exists() {
            return Some((json_path, false));
        }
    }

    None
}

/// Get custom server config from a config file in the same directory as the executable.
/// Supports both encrypted (.enc) and plain JSON (.json) formats.
/// Encrypted config has higher priority.
pub fn get_custom_server_from_config_file() -> ResultType<CustomServer> {
    let (config_path, is_encrypted) = find_config_file_path()
        .ok_or_else(|| hbb_common::anyhow::anyhow!("Config file not found"))?;

    log::debug!(
        "Found config file at: {:?} (encrypted: {})",
        config_path,
        is_encrypted
    );

    let content = std::fs::read_to_string(&config_path).map_err(|e| {
        log::warn!("Failed to read {}: {}", config_path.display(), e);
        hbb_common::anyhow::anyhow!("Failed to read {}: {}", config_path.display(), e)
    })?;

    let server: CustomServer = if is_encrypted {
        parse_encrypted_config(&content).map_err(|e| {
            log::warn!("Failed to decrypt {}: {}", config_path.display(), e);
            hbb_common::anyhow::anyhow!("Failed to decrypt {}: {}", config_path.display(), e)
        })?
    } else {
        log::debug!("Config file content: {}", content);
        serde_json::from_str(&content).map_err(|e| {
            log::warn!("Failed to parse {}: {}", config_path.display(), e);
            hbb_common::anyhow::anyhow!("Failed to parse {}: {}", config_path.display(), e)
        })?
    };

    // At least host should be non-empty to be valid
    if server.host.is_empty() {
        log::warn!("Host is empty in config file: {:?}", config_path);
        bail!("Host is empty in config file: {:?}", config_path);
    }

    log::info!(
        "Loaded custom server config from {:?} (encrypted: {}): host={}, key={}, api={}, relay={}",
        config_path,
        is_encrypted,
        server.host,
        if server.key.is_empty() {
            "(empty)"
        } else {
            "(set)"
        },
        if server.api.is_empty() {
            "(empty)"
        } else {
            &server.api
        },
        if server.relay.is_empty() {
            "(empty)"
        } else {
            &server.relay
        }
    );

    // Hide server settings in UI when config is loaded from file
    set_hide_server_settings();

    Ok(server)
}

pub fn get_custom_server_from_string(s: &str) -> ResultType<CustomServer> {
    // First try to read from config file
    if let Ok(server) = get_custom_server_from_config_file() {
        return Ok(server);
    }
    
    // Fall back to parsing from exe name
    let s = if s.to_lowercase().ends_with(".exe.exe") {
        &s[0..s.len() - 8]
    } else if s.to_lowercase().ends_with(".exe") {
        &s[0..s.len() - 4]
    } else {
        s
    };
    /*
     * The following code tokenizes the file name based on commas and
     * extracts relevant parts sequentially.
     *
     * host= is expected to be the first part.
     *
     * Since Windows renames files adding (1), (2) etc. before the .exe
     * in case of duplicates, which causes the host or key values to be
     * garbled.
     *
     * This allows using a ',' (comma) symbol as a final delimiter.
     */
    if s.to_lowercase().contains("host=") {
        let stripped = &s[s.to_lowercase().find("host=").unwrap_or(0)..s.len()];
        let strs: Vec<&str> = stripped.split(",").collect();
        let mut host = String::default();
        let mut key = String::default();
        let mut api = String::default();
        let mut relay = String::default();
        let strs_iter = strs.iter();
        for el in strs_iter {
            let el_lower = el.to_lowercase();
            if el_lower.starts_with("host=") {
                host = el.chars().skip(5).collect();
            }
            if el_lower.starts_with("key=") {
                key = el.chars().skip(4).collect();
            }
            if el_lower.starts_with("api=") {
                api = el.chars().skip(4).collect();
            }
            if el_lower.starts_with("relay=") {
                relay = el.chars().skip(6).collect();
            }
        }
        return Ok(CustomServer {
            host,
            key,
            api,
            relay,
        });
    } else {
        let s = s
            .replace("-licensed---", "--")
            .replace("-licensed--", "--")
            .replace("-licensed-", "--");
        let strs = s.split("--");
        for s in strs {
            if let Ok(lic) = get_custom_server_from_config_string(s.trim()) {
                return Ok(lic);
            } else if s.contains("(") {
                // https://github.com/rustdesk/rustdesk/issues/4162
                for s in s.split("(") {
                    if let Ok(lic) = get_custom_server_from_config_string(s.trim()) {
                        return Ok(lic);
                    }
                }
            }
        }
    }
    bail!("Failed to parse");
}

/// Command line tool to generate encrypted config
/// Usage: rustdesk --encrypt-config <json_file> [output_file]
pub fn encrypt_config_file(input_path: &str, output_path: Option<&str>) -> ResultType<()> {
    let content = std::fs::read_to_string(input_path)?;
    let server: CustomServer = serde_json::from_str(&content)?;
    
    if server.host.is_empty() {
        bail!("Host cannot be empty");
    }
    
    let encrypted = generate_encrypted_config(&server)?;
    
    let output = output_path
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            let path = std::path::Path::new(input_path);
            let parent = path.parent().unwrap_or(std::path::Path::new("."));
            parent.join(ENCRYPTED_CONFIG_FILE_NAME).to_string_lossy().to_string()
        });
    
    std::fs::write(&output, &encrypted)?;
    println!("Encrypted config written to: {}", output);
    println!("Original config: host={}, key={}, api={}, relay={}", 
        server.host,
        if server.key.is_empty() { "(empty)" } else { "(set)" },
        if server.api.is_empty() { "(empty)" } else { &server.api },
        if server.relay.is_empty() { "(empty)" } else { &server.relay }
    );
    
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_config_file_parsing() {
        let json = r#"{"host": "server.example.net", "key": "testkey", "api": "https://api.example.net", "relay": "relay.example.net"}"#;
        let server: CustomServer = serde_json::from_str(json).unwrap();
        assert_eq!(server.host, "server.example.net");
        assert_eq!(server.key, "testkey");
        assert_eq!(server.api, "https://api.example.net");
        assert_eq!(server.relay, "relay.example.net");

        // Test with empty optional fields
        let json_minimal = r#"{"host": "server.example.net"}"#;
        let server_minimal: CustomServer = serde_json::from_str(json_minimal).unwrap();
        assert_eq!(server_minimal.host, "server.example.net");
        assert_eq!(server_minimal.key, "");
        assert_eq!(server_minimal.api, "");
        assert_eq!(server_minimal.relay, "");
    }

    #[test]
    fn test_encrypt_decrypt_config() {
        let server = CustomServer {
            host: "test.example.com".to_owned(),
            key: "test_key_123".to_owned(),
            api: "https://api.example.com".to_owned(),
            relay: "relay.example.com".to_owned(),
        };
        
        // Encrypt
        let encrypted = generate_encrypted_config(&server).unwrap();
        assert!(!encrypted.is_empty());
        
        // Decrypt
        let decrypted = parse_encrypted_config(&encrypted).unwrap();
        assert_eq!(decrypted.host, server.host);
        assert_eq!(decrypted.key, server.key);
        assert_eq!(decrypted.api, server.api);
        assert_eq!(decrypted.relay, server.relay);
    }

    #[test]
    fn test_filename_license_string() {
        assert!(get_custom_server_from_string("rustdesk.exe").is_err());
        assert!(get_custom_server_from_string("rustdesk").is_err());
        assert_eq!(
            get_custom_server_from_string("rustdesk-host=server.example.net.exe").unwrap(),
            CustomServer {
                host: "server.example.net".to_owned(),
                key: "".to_owned(),
                api: "".to_owned(),
                relay: "".to_owned(),
            }
        );
        assert_eq!(
            get_custom_server_from_string("rustdesk-host=server.example.net,.exe").unwrap(),
            CustomServer {
                host: "server.example.net".to_owned(),
                key: "".to_owned(),
                api: "".to_owned(),
                relay: "".to_owned(),
            }
        );
        // key in these tests is "foobar.,2" base64 encoded
        assert_eq!(
            get_custom_server_from_string(
                "rustdesk-host=server.example.net,api=abc,key=Zm9vYmFyLiwyCg==.exe"
            )
            .unwrap(),
            CustomServer {
                host: "server.example.net".to_owned(),
                key: "Zm9vYmFyLiwyCg==".to_owned(),
                api: "abc".to_owned(),
                relay: "".to_owned(),
            }
        );
        assert_eq!(
            get_custom_server_from_string(
                "rustdesk-host=server.example.net,key=Zm9vYmFyLiwyCg==,.exe"
            )
            .unwrap(),
            CustomServer {
                host: "server.example.net".to_owned(),
                key: "Zm9vYmFyLiwyCg==".to_owned(),
                api: "".to_owned(),
                relay: "".to_owned(),
            }
        );
        assert_eq!(
            get_custom_server_from_string(
                "rustdesk-host=server.example.net,key=Zm9vYmFyLiwyCg==,relay=server.example.net.exe"
            )
            .unwrap(),
            CustomServer {
                host: "server.example.net".to_owned(),
                key: "Zm9vYmFyLiwyCg==".to_owned(),
                api: "".to_owned(),
                relay: "server.example.net".to_owned(),
            }
        );
        assert_eq!(
            get_custom_server_from_string(
                "rustdesk-Host=server.example.net,Key=Zm9vYmFyLiwyCg==,RELAY=server.example.net.exe"
            )
            .unwrap(),
            CustomServer {
                host: "server.example.net".to_owned(),
                key: "Zm9vYmFyLiwyCg==".to_owned(),
                api: "".to_owned(),
                relay: "server.example.net".to_owned(),
            }
        );
        let lic = CustomServer {
            host: "1.1.1.1".to_owned(),
            key: "5Qbwsde3unUcJBtrx9ZkvUmwFNoExHzpryHuPUdqlWM=".to_owned(),
            api: "".to_owned(),
            relay: "".to_owned(),
        };
        assert_eq!(
            get_custom_server_from_string("rustdesk-licensed-0nI900VsFHZVBVdIlncwpHS4V0bOZ0dtVldrpVO4JHdCp0YV5WdzUGZzdnYRVjI6ISeltmIsISMuEjLx4SMiojI0N3boJye.exe")
                .unwrap(), lic);
        assert_eq!(
            get_custom_server_from_string("rustdesk-licensed-0nI900VsFHZVBVdIlncwpHS4V0bOZ0dtVldrpVO4JHdCp0YV5WdzUGZzdnYRVjI6ISeltmIsISMuEjLx4SMiojI0N3boJye(1).exe")
                .unwrap(), lic);
        assert_eq!(
            get_custom_server_from_string("rustdesk--0nI900VsFHZVBVdIlncwpHS4V0bOZ0dtVldrpVO4JHdCp0YV5WdzUGZzdnYRVjI6ISeltmIsISMuEjLx4SMiojI0N3boJye(1).exe")
                .unwrap(), lic);
        assert_eq!(
            get_custom_server_from_string("rustdesk-licensed-0nI900VsFHZVBVdIlncwpHS4V0bOZ0dtVldrpVO4JHdCp0YV5WdzUGZzdnYRVjI6ISeltmIsISMuEjLx4SMiojI0N3boJye (1).exe")
                .unwrap(), lic);
        assert_eq!(
            get_custom_server_from_string("rustdesk-licensed-0nI900VsFHZVBVdIlncwpHS4V0bOZ0dtVldrpVO4JHdCp0YV5WdzUGZzdnYRVjI6ISeltmIsISMuEjLx4SMiojI0N3boJye (1) (2).exe")
                .unwrap(), lic);
        assert_eq!(
            get_custom_server_from_string("rustdesk-licensed-0nI900VsFHZVBVdIlncwpHS4V0bOZ0dtVldrpVO4JHdCp0YV5WdzUGZzdnYRVjI6ISeltmIsISMuEjLx4SMiojI0N3boJye--abc.exe")
                .unwrap(), lic);
        assert_eq!(
            get_custom_server_from_string("rustdesk-licensed--0nI900VsFHZVBVdIlncwpHS4V0bOZ0dtVldrpVO4JHdCp0YV5WdzUGZzdnYRVjI6ISeltmIsISMuEjLx4SMiojI0N3boJye--.exe")
                .unwrap(), lic);
        assert_eq!(
            get_custom_server_from_string("rustdesk-licensed---0nI900VsFHZVBVdIlncwpHS4V0bOZ0dtVldrpVO4JHdCp0YV5WdzUGZzdnYRVjI6ISeltmIsISMuEjLx4SMiojI0N3boJye--.exe")
                .unwrap(), lic);
        assert_eq!(
            get_custom_server_from_string("rustdesk-licensed--0nI900VsFHZVBVdIlncwpHS4V0bOZ0dtVldrpVO4JHdCp0YV5WdzUGZzdnYRVjI6ISeltmIsISMuEjLx4SMiojI0N3boJye--.exe")
                .unwrap(), lic);
    }
}
