use crate::utils::{
    new_stealth_address,
    new_stealth_address_from_registry,
    hexlify,
    unhexlify
};
use crate::constants::{
    REGISTRY_ADDRESS,
    get_default_chain_id,
    get_default_rpc
};

pub async fn run(
    receiver: Option<String>,
    chain_id: Option<u64>,
    rpc: Option<String>,
    meta_address: Option<String>,
) -> std::io::Result<()> {
    let sma = match meta_address {
        Some(meta_address) => meta_address,
        None => "".to_string(),
    };
    let stealth_address: [u8; 20];
    let ephemeral_pubkey: [u8; 33];
    let view_tag: u8;
    if sma != "" {
        (stealth_address, ephemeral_pubkey, view_tag) = new_stealth_address(unhexlify(&sma).as_slice().try_into().unwrap());
    } else {
        let address = match receiver {
            Some(receiver) => receiver,
            None => panic!("missing required --address argument (-a)"),
        };
        let chain_id = match chain_id {
            Some(chain_id) => chain_id,
            None => get_default_chain_id(),
        };
        let rpc = match rpc {
            Some(rpc) => rpc,
            None => get_default_rpc(&chain_id),
        };
        (stealth_address, ephemeral_pubkey, view_tag) = new_stealth_address_from_registry(&address, &rpc, &REGISTRY_ADDRESS.to_string()).await;
    }
    println!(
        "------ STEALTH ADDRESS ------\nschemeId: {}\nstealth address: {}\nephepmeral pubkey: {}\nview tag: {}",
        1,
        hexlify(&stealth_address),
        hexlify(&ephemeral_pubkey),
        view_tag
    );
    Ok(())
}
