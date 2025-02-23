use crate::constants::{get_default_chain_id, DEFAULT_KEYSTORE_DIR};
use crate::utils::{get_stealth_key, hexlify, load_encrypted_logfile, load_stealth_keys};
use alloy::primitives::{Address, Bytes};
use rpassword::prompt_password;
use std::path::PathBuf;
use std::str::FromStr;

pub fn run(
    keystore: Option<PathBuf>,
    chain_id: Option<u64>,
    address: Option<String>,
    ephemeral_pubkey: Option<String>,
) -> std::io::Result<()> {
    let stealth_address = match address {
        Some(address) => address,
        None => panic!("missing required --address argument (-a)"),
    };
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
    let stealth_key: [u8; 32];
    match ephemeral_pubkey {
        Some(ephemeral_pubkey) => {
            stealth_key = get_stealth_key(
                Address::from_str(&stealth_address).unwrap(),
                Bytes::from_str(&ephemeral_pubkey).unwrap(),
                sk,
                vk,
            );
        }
        None => {
            let logfile = load_encrypted_logfile(&password, &ks);
            let payment = logfile
                .logs
                .iter()
                .find(|p| p.stealth_address == Address::from_str(&stealth_address).unwrap());
            match payment {
                Some(payment) => {
                    stealth_key = get_stealth_key(
                        payment.stealth_address,
                        payment.ephemeral_pubkey.clone(),
                        sk,
                        vk,
                    );
                }
                None => {
                    panic!("No payment found for address {}", stealth_address);
                }
            }
        }
    };
    println!("-------- ETHEREUM ACCOUNT PRIVATE KEY --------");
    println!("{}", hexlify(&stealth_key));
    Ok(())
}
