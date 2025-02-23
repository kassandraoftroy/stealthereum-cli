use crate::utils::{
    format_u256_as_decimal,
    get_stealth_meta_address,
    load_encrypted_logfile,
    load_stealth_keys,
    load_wallet_from_priv_or_account,
    Logfile,
    hexlify
};
use std::collections::HashSet;
use std::path::PathBuf;
use std::str::FromStr;
use rpassword::prompt_password;
use alloy::{
    primitives::{Address, U256},
    providers::{ProviderBuilder, Provider},
    contract::{ContractInstance, Interface},
    dyn_abi::DynSolValue,
    json_abi::JsonAbi,
};
use crate::constants::{get_default_chain_id, get_default_rpc, DEFAULT_KEYSTORE_DIR, PUBLIC_ACCT_FILENAME};

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
    itemized: bool
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
        },
    };
    let rpc = match rpc {
        Some(rpc) => rpc,
        None => get_default_rpc(&chain_id),
    };
    let password = prompt_password("Enter stealthereum password:").expect("Failed to read password");
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
    println!("\n----- ITEMIZED BALANCES -----\n");
    if itemized {
        for ab in address_bals {
            println!("    {}", ab.address.to_string());
            render_token_balances(&ab.balances, &metadatas, 1);
        }
    }
    println!("\n----- STEALTHEREUM PUBLIC INFO -----\n");
    println!("Stealth Meta Address: {}", hexlify(&sma));
    if public_address != Address::ZERO {
        println!("Public Address: {}", public_address.to_string());
        println!("(balances of Public Address are not included)");
    }
    println!("\n----- STEALTHEREUM HOLDINGS -----\n");
    render_token_balances(&bals, &metadatas, 0);
    Ok(())
}

fn get_address_and_token_sets(logfile: &Logfile) -> (Vec<Address>, Vec<Address>) {
    let addresses: Vec<Address> = logfile.logs.iter().map(|l| l.stealth_address).collect();
    let tokens: Vec<Address> = logfile.logs.iter().flat_map(|l| l.parsed_transfers.iter().map(|t| t.token)).collect();
    let address_set: HashSet<Address> = addresses.into_iter().collect();
    let tokens_set: HashSet<Address> = tokens.into_iter().collect();
    (address_set.into_iter().collect(), tokens_set.into_iter().collect())
}

async fn get_balances(addresses: &Vec<Address>, tokens: &Vec<Address>, rpc: &String) -> (Vec<TokenValue>, Vec<AddressBalance>, Vec<TokenMetadata>) {
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_http(rpc.parse().unwrap());
    let abi = JsonAbi::parse([
        "function supportsInterface(bytes4) external view returns (bool)",
        "function symbol() external view returns (string)",
        "function decimals() external view returns (uint8)",
        "function balanceOf(address) external view returns (uint256)",
    ]).expect("Failed to parse ABI");
    let iface = Interface::new(abi);
    let mut metadatas = Vec::new();
    for token in tokens {
        if *token != Address::from_str("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap() {
            let contract = ContractInstance::new(*token, provider.clone(), iface.clone());

            // Check if token is ERC721 by calling supportsInterface with ERC721 interface ID
            let is_nft = match contract.clone()
                .function("supportsInterface", &[
                    DynSolValue::Bytes(hex::decode("80ac58cd").unwrap().try_into().unwrap())
                ])
                .expect("Failed to create method call")
                .call()
                .await {
                    Ok(result) => result[0].as_bool().unwrap_or(false),
                    Err(_) => false
                };
            let decimals;
            if is_nft { 
                decimals = 0;
            } else {
                decimals = match contract
                    .function("decimals", &[])
                    .expect("Failed to create method call")
                    .call()
                    .await {
                        Ok(result) => result[0].as_bytes().unwrap_or(&[0; 32])[0] as u8,
                        Err(_) => 0
                    };
            }

            let symbol = match contract
                .function("symbol", &[])
                .expect("Failed to create method call")
                .call()
                .await {
                    Ok(r) => String::from_utf8_lossy(r[0].as_bytes().unwrap_or(&[])).to_string(),
                    Err(_) => "".to_string()
                };
            metadatas.push(TokenMetadata { symbol: symbol.to_string(), decimals, is_nft });
        } else {
            metadatas.push(TokenMetadata { symbol: "ETH".to_string(), decimals: 18, is_nft: false });
        }
    }
    let mut address_balances: Vec<AddressBalance> = Vec::new();
    let mut totals = vec![U256::ZERO; tokens.len()];
    for address in addresses {
        let mut balances = Vec::new();
        for i in 0..tokens.len() {
            if tokens[i] != Address::from_str("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap() {
                let contract = ContractInstance::new(tokens[i], provider.clone(), iface.clone());
                let (balance, _) = contract.function("balanceOf", &[DynSolValue::Address(*address)]).expect("Failed to create method call").call().await.unwrap()[0].as_uint().unwrap();
                balances.push(TokenValue { token: tokens[i], value: balance });
                totals[i] += balance;
            } else {
                let balance = provider.get_balance(*address).await.unwrap();
                balances.push(TokenValue { token: tokens[i], value: balance });
                totals[i] += balance;
            }
        }
        address_balances.push(AddressBalance { address: *address, balances });
    }
    let bals = totals.into_iter().zip(tokens.iter()).map(|(value, token)| TokenValue {
        token: *token,
        value
    }).collect::<Vec<TokenValue>>();
    (bals, address_balances, metadatas)
}

fn render_token_balances(balances: &Vec<TokenValue>, metadatas: &Vec<TokenMetadata>, n: usize) {
    println!("{}TOKENS:", " ".repeat(8*n));
    for (i, balance) in balances.iter().enumerate() {
        if !metadatas[i].is_nft {
            let symbol = if metadatas[i].symbol == "" {
                balance.token.to_string()
            } else {
                metadatas[i].symbol.clone()
            };
            println!("{}{}: {}", " ".repeat(4+8*n), symbol, format_u256_as_decimal(balance.value, metadatas[i].decimals));
        }
    }
    println!("{}NFTS:", " ".repeat(8*n));
    for (i, balance) in balances.iter().enumerate() {
        if metadatas[i].is_nft {
            let symbol = if metadatas[i].symbol == "" {
                balance.token.to_string()
            } else {
                metadatas[i].symbol.clone()
            };
            println!("{}{}: {}", " ".repeat(4+8*n), symbol, balance.value.to_string());
        }
    }
}
