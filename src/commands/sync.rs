use crate::constants::{
    get_default_chain_id, get_default_rpc, get_default_starting_block, ANNOUNCER_ADDRESS,
    DEFAULT_KEYSTORE_DIR, ENCRYPTED_LOGS_FILENAME,
};
use crate::utils::{
    load_encrypted_logfile, load_stealth_keys, scan_for_payments, store_encrypted_logfile, Logfile,
};
use rpassword::prompt_password;
use std::path::PathBuf;

pub async fn run(
    keystore: Option<PathBuf>,
    chain_id: Option<u64>,
    rpc: Option<String>,
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
        }
    };
    let rpc = match rpc {
        Some(rpc) => rpc,
        None => get_default_rpc(&chain_id),
    };
    let password =
        prompt_password("Enter stealthereum password:").expect("Failed to read password");
    let (sk, vk) = load_stealth_keys(&ks, &password);
    let logfile: Logfile;
    if !ks.join(ENCRYPTED_LOGS_FILENAME).exists() {
        logfile = Logfile {
            logs: vec![],
            latest_block: get_default_starting_block(&chain_id),
        };
    } else {
        logfile = load_encrypted_logfile(&password, &ks);
    }
    println!("Starting sync from block: {}...", logfile.latest_block);
    let (payments, latest_block) = scan_for_payments(
        &rpc,
        &ANNOUNCER_ADDRESS.to_string(),
        &logfile.latest_block,
        sk,
        vk,
    )
    .await;
    println!(
        "Found {} new payments, storing to keystore...",
        payments.len()
    );
    let new_logfile = Logfile {
        logs: [logfile.logs, payments].concat(),
        latest_block: latest_block,
    };
    store_encrypted_logfile(&password, &ks, &new_logfile);
    println!("Sync complete! Latest block: {}", latest_block);
    Ok(())
}
