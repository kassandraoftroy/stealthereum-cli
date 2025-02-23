use crate::constants::{
    get_default_chain_id, DEFAULT_KEYSTORE_DIR, PUBLIC_ACCT_FILENAME, SECRET_KEY_FILENAME,
};
use crate::utils::{copy_public_account, create_public_account, unhexlify};
use rpassword::prompt_password;
use std::path::PathBuf;

pub fn run(
    keystore: Option<PathBuf>,
    chain_id: Option<u64>,
    private_key: Option<String>,
    account: Option<String>,
    interactive: bool,
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
            default_path
        }
    };
    if ks.join(PUBLIC_ACCT_FILENAME).exists() {
        panic!("Public account file already exists at {}", ks.display());
    }
    if !ks.join(SECRET_KEY_FILENAME).exists() {
        panic!("stealth keys do not exist in this keystore directory, run `keygen` command first");
    }
    let password =
        prompt_password("Enter stealthereum password:").expect("Failed to read password");
    match account {
        Some(account) => {
            let old_pwd = prompt_password("Enter current account password:")
                .expect("Failed to read password");
            copy_public_account(&account, &ks, &password, &old_pwd);
        }
        None => {
            if interactive {
                let priv_hex =
                    prompt_password("Enter Private Key Hex:").expect("Failed to read private key");
                let priv_vec = unhexlify(&priv_hex);
                create_public_account(&priv_vec, &ks, &password);
            } else {
                let priv_hex = match private_key {
                    Some(private_key) => private_key,
                    None => panic!("missing required --private-key argument (-p)"),
                };
                let priv_vec = unhexlify(&priv_hex);
                create_public_account(&priv_vec, &ks, &password);
            }
        }
    };
    println!("\nPublic account imported successfully!\n");
    println!(
        "Public account keyfile:\n{}",
        ks.join(PUBLIC_ACCT_FILENAME).display()
    );
    Ok(())
}
