use base64::{engine::general_purpose::STANDARD, Engine};
use keyring::Entry;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

const SERVICE: &str = "fr.louisraille.coucou.chatgpt";
const CHUNK_SIZE: usize = 1000;
const MAX_CHUNKS: usize = 256;
static STORAGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Serialize, Deserialize)]
struct Manifest {
    generation: String,
    chunks: usize,
}

fn credential(name: &str) -> Result<Entry, String> {
    Entry::new(SERVICE, name).map_err(|_| "Could not access ChatGPT credential storage.".into())
}

trait Credentials {
    fn read(&self, name: &str) -> Result<Option<String>, String>;
    fn write(&self, name: &str, value: &str) -> Result<(), String>;
    fn remove(&self, name: &str) -> Result<(), String>;
}

struct WindowsCredentials;

impl Credentials for WindowsCredentials {
    fn read(&self, name: &str) -> Result<Option<String>, String> {
        match credential(name)?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => {
                Err("Could not read ChatGPT credentials from Windows Credential Manager.".into())
            }
        }
    }

    fn write(&self, name: &str, value: &str) -> Result<(), String> {
        credential(name)?
            .set_password(value)
            .map_err(|_| "Could not save ChatGPT credentials in Windows Credential Manager.".into())
    }

    fn remove(&self, name: &str) -> Result<(), String> {
        match credential(name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err("Could not remove old ChatGPT credential fragments from Windows Credential Manager.".into()),
        }
    }
}

fn manifest(credentials: &impl Credentials) -> Result<Option<Manifest>, String> {
    credentials
        .read("manifest")?
        .map(|value| {
            let manifest: Manifest = serde_json::from_str(&value)
                .map_err(|_| "ChatGPT credential storage is invalid.".to_string())?;
            if manifest.generation.len() != 32
                || !manifest.generation.bytes().all(|b| b.is_ascii_hexdigit())
                || manifest.chunks == 0
                || manifest.chunks > MAX_CHUNKS
            {
                return Err("ChatGPT credential storage is invalid.".into());
            }
            Ok(manifest)
        })
        .transpose()
}

fn chunk_name(manifest: &Manifest, index: usize) -> String {
    format!("{}-{index}", manifest.generation)
}

fn remove_chunks(credentials: &impl Credentials, manifest: &Manifest) -> Result<(), String> {
    let mut failure = None;
    for index in 0..manifest.chunks {
        if let Err(error) = credentials.remove(&chunk_name(manifest, index)) {
            failure = Some(error);
        }
    }
    failure.map_or(Ok(()), Err)
}

pub fn load<T: DeserializeOwned + Default>() -> Result<T, String> {
    let _storage = STORAGE_LOCK.lock().unwrap();
    load_with(&WindowsCredentials)
}

fn load_with<T: DeserializeOwned + Default>(credentials: &impl Credentials) -> Result<T, String> {
    let Some(manifest) = manifest(credentials)? else {
        return Ok(T::default());
    };
    let mut encoded = String::new();
    for index in 0..manifest.chunks {
        let chunk = credentials
            .read(&chunk_name(&manifest, index))?
            .ok_or_else(|| "ChatGPT credential storage is incomplete.".to_string())?;
        encoded.push_str(&chunk);
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| "ChatGPT credential storage is invalid.".to_string())?;
    serde_json::from_slice(&bytes).map_err(|_| "ChatGPT credential storage is invalid.".into())
}

pub fn save<T: Serialize>(value: &T) -> Result<(), String> {
    let _storage = STORAGE_LOCK.lock().unwrap();
    save_with(&WindowsCredentials, value)
}

fn save_with<T: Serialize>(credentials: &impl Credentials, value: &T) -> Result<(), String> {
    let previous = manifest(credentials)?;
    let bytes = serde_json::to_vec(value)
        .map_err(|_| "Could not encode ChatGPT credentials.".to_string())?;
    let encoded = STANDARD.encode(bytes);
    let next = Manifest {
        generation: crate::chatgpt::random_hex(16)?,
        chunks: encoded.len().div_ceil(CHUNK_SIZE),
    };
    if next.chunks > MAX_CHUNKS {
        return Err("ChatGPT credential storage is full.".into());
    }
    let result = (|| {
        for (index, chunk) in encoded.as_bytes().chunks(CHUNK_SIZE).enumerate() {
            credentials.write(
                &chunk_name(&next, index),
                std::str::from_utf8(chunk).unwrap(),
            )?;
        }
        let manifest = serde_json::to_string(&next)
            .map_err(|_| "Could not encode ChatGPT credential manifest.".to_string())?;
        credentials.write("manifest", &manifest)
    })();
    if result.is_err() {
        remove_chunks(credentials, &next)?;
    } else if let Some(previous) = previous {
        remove_chunks(credentials, &previous)?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    #[derive(Default)]
    struct MemoryCredentials {
        entries: RefCell<HashMap<String, String>>,
        writes_left: Cell<Option<usize>>,
    }

    impl Credentials for MemoryCredentials {
        fn read(&self, name: &str) -> Result<Option<String>, String> {
            Ok(self.entries.borrow().get(name).cloned())
        }

        fn write(&self, name: &str, value: &str) -> Result<(), String> {
            if let Some(left) = self.writes_left.get() {
                if left == 0 {
                    return Err("Simulated storage failure".into());
                }
                self.writes_left.set(Some(left - 1));
            }
            assert!(value.encode_utf16().count() * 2 <= 2560);
            self.entries.borrow_mut().insert(name.into(), value.into());
            Ok(())
        }

        fn remove(&self, name: &str) -> Result<(), String> {
            self.entries.borrow_mut().remove(name);
            Ok(())
        }
    }

    #[test]
    fn long_unicode_credentials_round_trip_and_rotation_removes_old_tokens() {
        let credentials = MemoryCredentials::default();
        let value = "\u{00e9}".repeat(8000);
        save_with(&credentials, &value).unwrap();
        assert_eq!(load_with::<String>(&credentials).unwrap(), value);
        save_with(&credentials, &"replacement").unwrap();
        assert_eq!(load_with::<String>(&credentials).unwrap(), "replacement");
        assert_eq!(credentials.entries.borrow().len(), 2);
    }

    #[test]
    fn failed_chunk_or_manifest_write_keeps_previous_credentials() {
        for writes in [0, 1, 2] {
            let credentials = MemoryCredentials::default();
            save_with(&credentials, &"previous").unwrap();
            credentials.writes_left.set(Some(writes));
            assert!(save_with(&credentials, &"new".repeat(400)).is_err());
            assert_eq!(load_with::<String>(&credentials).unwrap(), "previous");
            assert_eq!(credentials.entries.borrow().len(), 2);
        }
    }

    #[test]
    fn missing_chunk_is_reported_instead_of_silently_resetting_session() {
        let credentials = MemoryCredentials::default();
        save_with(&credentials, &"saved").unwrap();
        let manifest = manifest(&credentials).unwrap().unwrap();
        credentials.remove(&chunk_name(&manifest, 0)).unwrap();
        assert!(load_with::<String>(&credentials).is_err());
    }
}
