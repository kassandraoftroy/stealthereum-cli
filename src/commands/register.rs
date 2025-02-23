use crate::constants::{
    get_default_chain_id, get_default_rpc, DEFAULT_KEYSTORE_DIR, PUBLIC_ACCT_FILENAME,
    REGISTRY_ADDRESS,
};
use crate::utils::{
    get_stealth_meta_address, get_stealth_meta_address_from_registry, hexlify, load_stealth_keys,
    load_wallet_from_priv_or_account, unhexlify,
};
use alloy::{
    network::EthereumWallet,
    primitives::{Address, Bytes, U256},
    providers::ProviderBuilder,
    sol,
};
use rpassword::prompt_password;
use std::path::PathBuf;
use std::str::FromStr;

sol! {
    #[sol(rpc)]
    interface IRegistry {
        function registerKeys(uint256 schemeId, bytes calldata stealthMetaAddress) external;
    }
}

pub async fn run(
    keystore: Option<PathBuf>,
    meta_address: Option<String>,
    rpc: Option<String>,
    chain_id: Option<u64>,
    account: Option<String>,
    private_key: Option<String>,
    overwrite: bool,
) -> std::io::Result<()> {
    let sma = match meta_address {
        Some(meta_address) => meta_address,
        None => "".to_string(),
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
            default_path
        }
    };
    let mut password: String = "".to_string();
    let stealth_meta_address: [u8; 66];
    if sma != "" {
        stealth_meta_address = unhexlify(&sma).as_slice().try_into().unwrap()
    } else {
        password =
            prompt_password("Enter stealthereum password:").expect("Failed to read password");
        let (sk, vk) = load_stealth_keys(&ks, &password);
        stealth_meta_address = get_stealth_meta_address(sk, vk);
    }
    let rpc = match rpc {
        Some(rpc) => rpc,
        None => get_default_rpc(&chain_id),
    };
    if account.is_some() {
        if account != Some(ks.join(PUBLIC_ACCT_FILENAME).to_string_lossy().to_string()) {
            println!("[WARN]: registering stealth meta address on custom account, consider importing account with `import-public-account` command first");
            password = prompt_password("Enter custom account password:")
                .expect("Failed to read account password");
        }
    }
    if !private_key.is_some() && password == "" {
        password =
            prompt_password("Enter stealthereum password:").expect("Failed to read password");
    }
    let (wallet, wallet_address) =
        load_wallet_from_priv_or_account(&private_key, &account, &password, &ks);
    let tx_hash = register_stealth_meta_address(
        wallet,
        &rpc,
        stealth_meta_address,
        &REGISTRY_ADDRESS.to_string(),
        wallet_address,
        overwrite,
    )
    .await;
    println!("Registration tx: {}", tx_hash);
    Ok(())
}

async fn register_stealth_meta_address(
    wallet: EthereumWallet,
    rpc: &String,
    stealth_meta_address: [u8; 66],
    registry_address: &String,
    wallet_address: Address,
    overwrite: bool,
) -> String {
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(rpc.parse().unwrap());
    let sma =
        get_stealth_meta_address_from_registry(&wallet_address.to_string(), rpc, registry_address)
            .await;
    if sma != [0; 66] && !overwrite {
        panic!("stealth meta address already registered: {}", hexlify(&sma));
    }
    let registry = IRegistry::new(
        Address::from_str(registry_address).unwrap(),
        provider.clone(),
    );
    let tx = registry
        .registerKeys(U256::from(1u64), Bytes::from(stealth_meta_address))
        .send()
        .await
        .unwrap();
    tx.tx_hash().to_string()
}
