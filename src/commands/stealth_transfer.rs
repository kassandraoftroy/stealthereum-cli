use crate::constants::{
    get_default_chain_id, get_default_rpc, get_stealthereum_address, DEFAULT_KEYSTORE_DIR,
    PUBLIC_ACCT_FILENAME, REGISTRY_ADDRESS,
};
use crate::utils::{
    load_wallet_from_priv_or_account, new_stealth_address, new_stealth_address_from_registry,
    unhexlify,
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
    interface IStealthereum {
        struct StealthTransfer {
            uint256 schemeId;
            address stealthAddress;
            bytes ephemeral_pubkeykey;
            uint8 viewTag;
            address[] tokens;
            uint256[] values;
            bytes extraMetadata;
        }

        function stealthTransfer(
            StealthTransfer calldata transferData
        ) external payable;
    }

    #[sol(rpc)]
    interface IApproval {
        function approve(address, uint256) external;
    }
}

pub async fn run(
    receiver: Option<String>,
    keystore: Option<PathBuf>,
    chain_id: Option<u64>,
    rpc: Option<String>,
    account: Option<String>,
    meta_address: Option<String>,
    token: Option<String>,
    value: Option<String>,
    private_key: Option<String>,
    skip_approval: bool,
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
    let rpc = match rpc {
        Some(rpc) => rpc,
        None => get_default_rpc(&chain_id),
    };
    let contract = get_stealthereum_address(&chain_id);

    let token = match token {
        Some(token) => token,
        None => "0x0000000000000000000000000000000000000000".to_string(),
    };
    let value = match value {
        Some(value) => value,
        None => panic!("missing required --value argument (-v)"),
    };
    let mut password: String = "".to_string();
    if account.is_some() {
        if account != Some(ks.join(PUBLIC_ACCT_FILENAME).to_string_lossy().to_string()) {
            password = prompt_password("Enter signer account password:")
                .expect("Failed to read account password");
        }
    }
    if !private_key.is_some() && password == "" {
        password =
            prompt_password("Enter stealthereum password:").expect("Failed to read password");
    }
    let (wallet, _) = load_wallet_from_priv_or_account(&private_key, &account, &password, &ks);

    let stealth_address: [u8; 20];
    let ephemeral_pubkey: [u8; 33];
    let view_tag: u8;
    if sma != "" {
        (stealth_address, ephemeral_pubkey, view_tag) =
            new_stealth_address(unhexlify(&sma).as_slice().try_into().unwrap());
    } else {
        let address = match receiver {
            Some(receiver) => receiver,
            None => panic!("missing required --address argument (-a)"),
        };
        (stealth_address, ephemeral_pubkey, view_tag) =
            new_stealth_address_from_registry(&address, &rpc, &REGISTRY_ADDRESS.to_string()).await;
    }

    stealth_transfer(
        wallet,
        &rpc,
        &contract,
        stealth_address,
        ephemeral_pubkey,
        view_tag,
        &token,
        &value,
        skip_approval,
    )
    .await;
    Ok(())
}

async fn stealth_transfer(
    wallet: EthereumWallet,
    rpc: &String,
    contract: &String,
    stealth_address: [u8; 20],
    ephemeral_pubkey: [u8; 33],
    view_tag: u8,
    token: &String,
    value: &String,
    skip_approval: bool,
) {
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(rpc.parse().unwrap());
    let stealthereum = IStealthereum::new(
        Address::from_str(contract.as_str()).unwrap(),
        provider.clone(),
    );

    let tokens: Vec<Address>;
    let values: Vec<U256>;
    let is_native = token == "0x0000000000000000000000000000000000000000"
        || token.to_lowercase() == "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    if !is_native {
        tokens = vec![Address::from_str(token).unwrap()];
        values = vec![U256::from_str(value).unwrap()];
        if !skip_approval {
            let token_contract =
                IApproval::new(Address::from_str(token).unwrap(), provider.clone());
            let tx = token_contract
                .approve(
                    Address::from_str(contract.as_str()).unwrap(),
                    U256::from_str(value).unwrap(),
                )
                .send()
                .await
                .unwrap();
            println!("Token Approval tx: {}...", tx.tx_hash());
            tx.watch().await.unwrap();
            println!("Token Approval confirmed");
        }
    } else {
        tokens = vec![];
        values = vec![];
    }
    let transfer_data = IStealthereum::StealthTransfer {
        schemeId: U256::from(1u64),
        stealthAddress: Address::from_slice(&stealth_address),
        ephemeral_pubkeykey: Bytes::from(ephemeral_pubkey),
        viewTag: view_tag,
        tokens: tokens,
        values: values,
        extraMetadata: Bytes::from_str("").unwrap(),
    };
    let eth_value = if is_native {
        U256::from_str(value).unwrap()
    } else {
        U256::from(0u64)
    };
    let tx = stealthereum
        .stealthTransfer(transfer_data)
        .value(eth_value)
        .send()
        .await
        .unwrap();
    println!("Stealth Transfer tx: {}", tx.tx_hash());
}
