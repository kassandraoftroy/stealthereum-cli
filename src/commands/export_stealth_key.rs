use crate::constants::{DEFAULT_KEYSTORE_DIR, get_default_chain_id};
use std::path::PathBuf;
use crate::utils::{
    get_stealth_key,
    load_stealth_keys,
    load_encrypted_logfile,
    hexlify
};
use rpassword::prompt_password;
use alloy::primitives::{Address, Bytes};
use std::str::FromStr;

pub fn run(
    keystore: Option<PathBuf>,
    chain_id: Option<u64>,
    address: Option<String>,
    stealthaddr: Option<String>,
    ephemeralpub: Option<String>
) -> std::io::Result<()> {
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
    let stealth_key: [u8; 32];
    match address {
        Some(address) => {
            let logfile = load_encrypted_logfile(&password, &ks);
            let payment = logfile.logs.iter().find(|p| p.stealth_address == Address::from_str(&address).unwrap());
            match payment {
                Some(payment) => {
                    stealth_key = get_stealth_key(payment.stealth_address, payment.ephemeral_pubkey.clone(), sk, vk);
                }
                None => {
                    panic!("No payment found for address {}", address);
                }
            }
        },
        None => {
            let sa = match stealthaddr {
                Some(stealthaddr) => stealthaddr.clone(),
                None => panic!("missing required --stealthaddr argument (-s)"),
            };
            let ep = match ephemeralpub {
                Some(ephemeralpub) => ephemeralpub.clone(),
                None => panic!("missing required --ephemeralpub argument (-e)"),
            };

            stealth_key = get_stealth_key(Address::from_str(&sa).unwrap(), Bytes::from_str(&ep).unwrap(), sk, vk);
        },
    };
    println!("-------- ETHEREUM ACCOUNT PRIVATE KEY --------");
    println!("{}", hexlify(&stealth_key));
    Ok(())
}
