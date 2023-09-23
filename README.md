# stealthereum-cli

This is a bare bones CLI written in rust for ERC-5564 compliant stealth address management on evm chains

It's currently the easiest way to interact with the [eth-stealth-addresses](https://github.com/kassandraoftroy/eth-stealth-addresses) rust library which implements the basic cryptographic operations necessary for a stealth addresses scheme over the secp256k1 curve (with view tags) as outlined [here](https://eips.ethereum.org/assets/eip-5564/scheme_ids)

For now it's extremely rough and low level! More improvements soon

NOT AUDITED - HOMEROLLED CRYPTO - USE AT YOUR OWN RISK

## Installation

```
cargo install stealthereum-cli
```

Make sure you add `$HOME/.cargo/bin` to your PATH

## Usage

Below is the list of basic commands and arguments for the CLI

#### keygen

generate a stealth meta address and store the keys

```bash
stealthereum keygen -o path/to/keyfile.json
```

#### stealth-address

generate all the components of a stealth address as defined in ERC-5564 given a target receiver's stealth meta address to privately send to

```bash
stealthereum stealth-address -r 0xReceiverStealthMetaAddres
```

#### reveal-stealth-key

compute the private key for a stealth address you control

```bash
stealthereum reveal-stealth-key -k path/to/keyfile.json -s 0xStealthAddress -e 0xEphemeralPub
```

note that this requires you to know in advance what `[stealth_address, ephemeral_pubkey]` pairs are actually payments meant for your stealth meta address (process will panic otherwise). See [scan](#scan) below for more info on how to scan for private payments to your stealth meta address

#### scan

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
        {
            "stealth_address": "0xSomeOtherAddress",
            "ephemeral_pubkey": "0xSomeOtherPubkey",
            "view_tag": 94
        }
    ]
}
```

#### show-meta-address

recompute your stealth meta address from keyfile

```bash
stealthereum show-meta-address -k path/to/keyfile.json
```
