use std::path::PathBuf;
use crate::constants::{DEFAULT_KEYSTORE_DIR, get_default_chain_id};
use crate::utils::{load_stealth_keys, get_stealth_meta_address, hexlify};
use rpassword::prompt_password;

pub fn run(keystore: Option<PathBuf>, chain_id: Option<u64>) -> std::io::Result<()> {
    let chain_id = match chain_id {
        Some(chain_id) => chain_id,
        None => get_default_chain_id(),
    };
    let ks = match keystore {
        Some(keystore) => keystore.join(chain_id.to_string()),
        None => {
            let mut default_path = dirs::home_dir().expect("Could not find home directory");
            default_path.push(DEFAULT_KEYSTORE_DIR);
            default_path.push(chain_id.to_string());
            default_path.clone()
        },
    };
    let password = prompt_password("Enter stealthereum password:").expect("Failed to read password");
    let (sk, vk) = load_stealth_keys(&ks, &password);
    let stealth_meta_address = get_stealth_meta_address(sk, vk);
    println!("------ STEALTH META ADDRESS ------\n{}", hexlify(&stealth_meta_address));
    Ok(())
}
