use crate::constants::{get_default_chain_id, DEFAULT_KEYSTORE_DIR, PUBLIC_ACCT_FILENAME};
use crate::utils::{
    get_stealth_meta_address, hexlify, load_encrypted_logfile, load_stealth_keys,
    load_wallet_from_priv_or_account,
};
use alloy::primitives::Address;
use rpassword::prompt_password;
use std::collections::HashSet;
use std::path::PathBuf;

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
        }
    };
    let password =
        prompt_password("Enter stealthereum password:").expect("Failed to read password");
    let (sk, vk) = load_stealth_keys(&ks, &password);
    let sma = get_stealth_meta_address(sk, vk);
    let logfile = load_encrypted_logfile(&password, &ks);
    let public_address;
    if ks.join(PUBLIC_ACCT_FILENAME).exists() {
        (_, public_address) = load_wallet_from_priv_or_account(&None, &None, &password, &ks);
    } else {
        public_address = Address::ZERO;
    }
    let stealth_addresses: HashSet<Address> =
        logfile.logs.iter().map(|p| p.stealth_address).collect();
    println!("\n----- STEALTHEREUM PUBLIC INFO -----\n");
    println!("Stealth Meta Address: {}", hexlify(&sma));
    if public_address != Address::ZERO {
        println!("Public Address: {}", public_address.to_string());
    }
    println!("\n----- STEALTH ADDRESSES -----\n");
    for stealth_address in stealth_addresses {
        println!("{}", stealth_address.to_string());
    }
    Ok(())
}
