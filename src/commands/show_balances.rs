use crate::constants::{
    get_default_chain_id, get_default_rpc, get_network_prefix, DEFAULT_KEYSTORE_DIR,
    PUBLIC_ACCT_FILENAME,
};
use crate::utils::{
    format_u256_as_decimal, get_stealth_meta_address, hexlify, load_encrypted_logfile,
    load_stealth_keys, load_wallet_from_priv_or_account, Logfile,
};
use alloy::{
    contract::{ContractInstance, Interface},
    dyn_abi::DynSolValue,
    json_abi::JsonAbi,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
};
use rpassword::prompt_password;
use std::collections::HashSet;
use std::path::PathBuf;
use std::str::FromStr;

struct TokenValue {
    token: Address,
    value: U256,
}

struct TokenMetadata {
    symbol: String,
    decimals: u8,
    is_nft: bool,
}

struct AddressBalance {
    address: Address,
    balances: Vec<TokenValue>,
}

pub async fn run(
    keystore: Option<PathBuf>,
    chain_id: Option<u64>,
    rpc: Option<String>,
    itemized: bool,
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
    let rpc = match rpc {
        Some(rpc) => rpc,
        None => get_default_rpc(&chain_id),
    };
    let password =
        prompt_password("Enter stealthereum password:").expect("Failed to read password");
    let logfile = load_encrypted_logfile(&password, &ks);
    let (sk, vk) = load_stealth_keys(&ks, &password);
    let sma = get_stealth_meta_address(sk, vk);
    let public_address;
    if ks.join(PUBLIC_ACCT_FILENAME).exists() {
        (_, public_address) = load_wallet_from_priv_or_account(&None, &None, &password, &ks);
    } else {
        public_address = Address::ZERO;
    }
    let (address_set, tokens_set) = get_address_and_token_sets(&logfile);
    let (bals, address_bals, metadatas) = get_balances(&address_set, &tokens_set, &rpc).await;

    if itemized {
        println!("\n----- ITEMIZED BALANCES -----\n");
        for ab in address_bals {
            println!(
                "    {}:{}",
                get_network_prefix(&chain_id),
                ab.address.to_string()
            );
            render_token_balances(&ab.balances, &metadatas, 1);
        }
    }

    println!("\n----- STEALTHEREUM PUBLIC INFO -----\n");
    println!(
        "Stealth Meta Address:\nst:{}:{}",
        get_network_prefix(&chain_id),
        hexlify(&sma)
    );
    if public_address != Address::ZERO {
        println!(
            "\nPublic Address: {}:{}",
            get_network_prefix(&chain_id),
            public_address.to_string()
        );
        println!("(balances of Public Address are not included)");
    }
    println!("\n----- STEALTHEREUM HOLDINGS -----\n");
    render_token_balances(&bals, &metadatas, 0);
    Ok(())
}

fn get_address_and_token_sets(logfile: &Logfile) -> (Vec<Address>, Vec<Address>) {
    let addresses: Vec<Address> = logfile.logs.iter().map(|l| l.stealth_address).collect();
    let tokens: Vec<Address> = logfile
        .logs
        .iter()
        .flat_map(|l| l.parsed_transfers.iter().map(|t| t.token))
        .collect();
    let address_set: HashSet<Address> = addresses.into_iter().collect();
    let tokens_set: HashSet<Address> = tokens.into_iter().collect();
    (
        address_set.into_iter().collect(),
        tokens_set.into_iter().collect(),
    )
}

async fn get_balances(
    addresses: &Vec<Address>,
    tokens: &Vec<Address>,
    rpc: &String,
) -> (Vec<TokenValue>, Vec<AddressBalance>, Vec<TokenMetadata>) {
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_http(rpc.parse().unwrap());
    let abi = JsonAbi::parse([
        "function isApprovedForAll(address owner, address operator) external view returns (bool)",
        "function symbol() external view returns (string memory)",
        "function decimals() external view returns (uint8)",
        "function balanceOf(address) external view returns (uint256)",
    ])
    .expect("Failed to parse ABI");
    let iface = Interface::new(abi);
    let mut metadatas = Vec::new();
    let eth_address = Address::from_str("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();
    for token in tokens {
        if *token != eth_address {
            let contract = ContractInstance::new(*token, provider.clone(), iface.clone());

            // Check if token is ERC721 by calling supportsInterface with ERC721 interface ID
            let is_nft = match contract
                .clone()
                .function(
                    "isApprovedForAll",
                    &[
                        DynSolValue::Address(addresses[0]),
                        DynSolValue::Address(eth_address),
                    ],
                )
                .expect("Failed to create method call")
                .call()
                .await
            {
                Ok(_) => true,
                Err(_) => false,
            };
            let decimals;
            if is_nft {
                decimals = 0;
            } else {
                decimals = match contract
                    .function("decimals", &[])
                    .expect("Failed to create method call")
                    .call()
                    .await
                {
                    Ok(result) => result[0]
                        .as_uint()
                        .unwrap_or((U256::ZERO, 8))
                        .0
                        .try_into()
                        .unwrap(),
                    Err(_) => 0,
                };
            }

            let symbol = match contract
                .function("symbol", &[])
                .expect("Failed to create method call")
                .call()
                .await
            {
                Ok(r) => r[0].as_str().unwrap_or("").to_string(),
                Err(_) => "".to_string(),
            };
            metadatas.push(TokenMetadata {
                symbol: symbol.to_string(),
                decimals,
                is_nft,
            });
        } else {
            metadatas.push(TokenMetadata {
                symbol: "ETH".to_string(),
                decimals: 18,
                is_nft: false,
            });
        }
    }
    let mut address_balances: Vec<AddressBalance> = Vec::new();
    let mut totals = vec![U256::ZERO; tokens.len()];
    for address in addresses {
        let mut balances = Vec::new();
        for i in 0..tokens.len() {
            if tokens[i] != Address::from_str("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap()
            {
                let contract = ContractInstance::new(tokens[i], provider.clone(), iface.clone());
                let (balance, _) = contract
                    .function("balanceOf", &[DynSolValue::Address(*address)])
                    .expect("Failed to create method call")
                    .call()
                    .await
                    .unwrap()[0]
                    .as_uint()
                    .unwrap();
                balances.push(TokenValue {
                    token: tokens[i],
                    value: balance,
                });
                totals[i] += balance;
            } else {
                let balance = provider.get_balance(*address).await.unwrap();
                balances.push(TokenValue {
                    token: tokens[i],
                    value: balance,
                });
                totals[i] += balance;
            }
        }
        address_balances.push(AddressBalance {
            address: *address,
            balances,
        });
    }
    let bals = totals
        .into_iter()
        .zip(tokens.iter())
        .map(|(value, token)| TokenValue {
            token: *token,
            value,
        })
        .collect::<Vec<TokenValue>>();
    (bals, address_balances, metadatas)
}

fn render_token_balances(balances: &Vec<TokenValue>, metadatas: &Vec<TokenMetadata>, n: usize) {
    let mut lines = Vec::new();
    for (i, balance) in balances.iter().enumerate() {
        if !metadatas[i].is_nft && balance.value > U256::ZERO {
            let symbol = if metadatas[i].symbol == "" {
                balance.token.to_string()
            } else {
                metadatas[i].symbol.clone()
            };
            lines.push(format!(
                "{}{}: {}",
                " ".repeat(4 + 8 * n),
                symbol,
                format_u256_as_decimal(balance.value, metadatas[i].decimals)
            ));
        }
    }
    if lines.len() > 0 {
        println!("{}TOKEN:", " ".repeat(8 * n));
        for line in lines {
            println!("{}", line);
        }
    }
    lines = Vec::new();
    for (i, balance) in balances.iter().enumerate() {
        if metadatas[i].is_nft && balance.value > U256::ZERO {
            let symbol = if metadatas[i].symbol == "" {
                balance.token.to_string()
            } else {
                metadatas[i].symbol.clone()
            };
            lines.push(format!(
                "{}{}: {}",
                " ".repeat(4 + 8 * n),
                symbol,
                balance.value.to_string()
            ));
        }
    }
    if lines.len() > 0 {
        println!("{}NFT:", " ".repeat(8 * n));
        for line in lines {
            println!("{}", line);
        }
    }
}
