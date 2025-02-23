use std::path::PathBuf;
use eth_stealth_addresses::generate_stealth_meta_address;
use rpassword::prompt_password;
use crate::utils::{hexlify, create_stealth_meta_keys, Logfile, store_encrypted_logfile};
use crate::constants::{SECRET_KEY_FILENAME, VIEWING_KEY_FILENAME, DEFAULT_KEYSTORE_DIR, ENCRYPTED_LOGS_FILENAME, get_default_starting_block, get_default_chain_id};

pub fn run(keystore: Option<PathBuf>, chain_id: Option<u64>) -> std::io::Result<()> {
    let chain_id = match chain_id {
        Some(chain_id) => chain_id,
        None => get_default_chain_id(),
    };
    let path = match keystore {
        Some(path) => path.join(chain_id.to_string()),
        None => {
            let mut default_path = dirs::home_dir().expect("Could not find home directory");
            default_path.push(DEFAULT_KEYSTORE_DIR);
            default_path.push(chain_id.to_string());
            default_path
        },
    };
    let starting_block = get_default_starting_block(&chain_id);
    let password = create_password();
    if path.join(SECRET_KEY_FILENAME).exists() || path.join(VIEWING_KEY_FILENAME).exists() || path.join(ENCRYPTED_LOGS_FILENAME).exists() {
        panic!("stealth keyfiles already exist in this keystore directory");
    }
    let (sma, sk, vk) = generate_stealth_meta_address();
    create_stealth_meta_keys(&path, &password, sk, vk);

    let logfile = Logfile{
        logs: vec![],
        latest_block: starting_block,
    };
    store_encrypted_logfile(&password, &path, &logfile);

    println!("\nCreated New Stealthereum Keystore!\n");
    println!("stored files:\n{}\n{}\n{}\n", path.join(SECRET_KEY_FILENAME).display(), path.join(VIEWING_KEY_FILENAME).display(), path.join(ENCRYPTED_LOGS_FILENAME).display());
    println!("------ STEALTH META ADDRESS ------\n{}", hexlify(&sma));
    Ok(())
}

fn create_password() -> String {
    let password = prompt_password("Enter stealthereum password:").expect("Failed to read password");
    let confirm_password = prompt_password("Confirm stealthereum password:").expect("Failed to read password");
    
    if password != confirm_password {
        panic!("Passwords do not match!");
    }
    
    password
}
