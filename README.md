# stealthereum-cli

This is a bare bones CLI written in rust for ERC-5564 compliant stealth address management on evm chains

It's currently the easiest way to interact with the [eth-stealth-addresses](https://github.com/kassandraoftroy/eth-stealth-addresses) rust library which implements the basic cryptographic operations necessary for a stealth addresses scheme over the secp256k1 curve (with view tags) as outlined [here](https://eips.ethereum.org/assets/eip-5564/scheme_ids)

For now it's extremely rough and low level! More improvements soon

## Installation

```
cargo install stealthereum-cli
```

Make sure you add `$HOME/.cargo/bin` to your PATH

## Usage

generate a stealth meta address and store the keys

```bash
stealthereum keygen -o path/to/keyfile.json
```

-----------------------

recompute your stealth meta address from keyfile

```bash
stealthereum show-meta-addr -k path/to/keyfile.json
```

-----------------------

generate all the components of a stealth transaction as defined in ERC-5564 given a target receiver and the desired asset(s) to sealthily transfer

```bash
stealthereum stealth-tx -r 0xReceiverStealthMetaAddres --msgvalue 1000000000000000000 --tokens 0x12970E6868f88f6557B76120662c1B3E50A646bf 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 --amounts 1 100000000
```

the above example would output:
1. a stealth address
2. an ephemeral public key and 
3. metadata for stealthily transferring (on mainnet) 1 ETH, a Milady (tokenId=1), and 100 USDC to the owner of the stealth meta address.

-----------------------

scan announced stealth transfers for payments to your stealth meta address

```bash
stealthereum scan -k path/to/keyfile.json -s path/to/scanfile.json
```

this will log the `[stealth_address, ephemeral_pubkey]` pairs of all stealth transfers that are claimable by you in the scanfile.

For now a scanfile has to be precomputed into a JSON format like so

```json
{
    "announcements": [
        {
            "stealth_address": "0xSomeStealthAddress",
            "ephemeral_pubkey": "0xSomeEphemeralPubkey",
            "view_tag": 116
        },
        ...
    ]
}
```

-----------------------

compute the private key for a stealth address you control

```bash
stealthereum reveal-stealth-key -k path/to/keyfile.json -s 0xSomeStealthAddress -e 0xSomeEphemeralPubkey
```
