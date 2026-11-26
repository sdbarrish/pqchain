//! `pqchain` command-line tool: demo, testnet setup, node daemon, wallet.

#![forbid(unsafe_code)]

mod demo;

use clap::{Parser, Subcommand};
use pqchain::crypto::{Address, Keypair, PublicKey, ALG_ML_DSA_65};
use pqchain::node::{self, chain_from_str, Allocation, Genesis, GenesisValidatorEntry, NodeConfig};
use pqchain::feistel::Action;
use pqchain::wallet::{self, Client};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "pqchain", version, about = "Post-quantum multi-chain blockchain (testnet)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the in-process v0 demo (simulated network).
    Demo,
    /// Create keys, genesis and configs for a local multi-node testnet.
    TestnetInit {
        #[arg(long, default_value = "testnet")]
        dir: PathBuf,
        #[arg(long, default_value_t = 4)]
        validators: usize,
        #[arg(long, default_value_t = 1)]
        full_nodes: usize,
        #[arg(long, default_value_t = 9100)]
        p2p_port: u16,
        #[arg(long, default_value_t = 8100)]
        rpc_port: u16,
        #[arg(long, default_value_t = 2_000)]
        stake: u64,
        #[arg(long, default_value_t = 10_000_000)]
        faucet: u64,
    },
    /// Run a node.
    Node {
        #[arg(long)]
        config: PathBuf,
    },
    /// Wallet commands (keys stay local; transactions are signed here).
    Wallet {
        /// Node RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:8100", global = true)]
        rpc: String,
        #[command(subcommand)]
        cmd: WalletCmd,
    },
}

#[derive(Subcommand)]
enum WalletCmd {
    /// Generate a new key file (ML-DSA-65, or SLH-DSA with --cold).
    New {
        #[arg(long)]
        out: PathBuf,
        /// Hash-based SLH-DSA-SHAKE-128s key for cold storage (e.g. validator withdrawal).
        #[arg(long)]
        cold: bool,
    },
    /// Encrypt an existing plaintext key file in place (passphrase from PQCHAIN_PASSPHRASE).
    EncryptKey {
        #[arg(long)]
        key: PathBuf,
    },
    /// Show a key file's address.
    Show {
        #[arg(long)]
        key: PathBuf,
    },
    /// Balances on both chains.
    Balance {
        #[arg(long, conflicts_with = "address")]
        key: Option<PathBuf>,
        #[arg(long)]
        address: Option<String>,
    },
    /// Pay someone.
    Send {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value = "atbash")]
        chain: String,
    },
    /// Move funds to the other chain (then run `import` there).
    Export {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value = "atbash")]
        from: String,
        #[arg(long, default_value = "kerckhoffs")]
        to: String,
    },
    /// Claim funds exported to a chain.
    Import {
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "kerckhoffs")]
        chain: String,
    },
    /// Register a validator (stake from the Kerckhoffs Chain).
    Stake {
        #[arg(long)]
        key: PathBuf,
        /// The new validator node's key file (only its public key is used).
        #[arg(long)]
        node_key: PathBuf,
        #[arg(long)]
        amount: u64,
    },
    /// Delegate stake to a validator.
    Delegate {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        node: String,
        #[arg(long)]
        amount: u64,
    },
    /// Register a zone (application chain) validated by the given primary validators.
    CreateZone {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        name: String,
        /// Comma-separated validator node ids (pq1...).
        #[arg(long, value_delimiter = ',')]
        members: Vec<String>,
    },
    /// Claim relay messages (transfers from/to zones) addressed to you on a chain.
    RelayImport {
        #[arg(long)]
        key: PathBuf,
        /// Receiving chain: atbash or zone-N.
        #[arg(long)]
        chain: String,
    },
    /// Claim staking rewards earned by this key's address (validator withdrawal
    /// address or delegator reward address); paid on the Kerckhoffs Chain.
    ClaimRewards {
        #[arg(long)]
        key: PathBuf,
    },
    /// Feistel Chain: claim funds exported from the Atbash Chain.
    FeistelImport {
        #[arg(long)]
        key: PathBuf,
    },
    /// Feistel Chain: send funds back to your Atbash Chain address.
    FeistelExport {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        amount: u64,
    },
    /// Feistel Chain: deploy a WebAssembly contract (.wasm or .wat).
    FeistelDeploy {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        code: PathBuf,
        #[arg(long, default_value_t = 5_000_000)]
        fuel: u64,
    },
    /// Feistel Chain: call a contract method.
    FeistelCall {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        contract: String,
        #[arg(long)]
        method: String,
        /// Input as hex.
        #[arg(long, default_value = "")]
        input: String,
        /// Native tokens to send with the call.
        #[arg(long, default_value_t = 0)]
        value: u64,
        #[arg(long, default_value_t = 1_000_000)]
        fuel: u64,
    },
    /// Feistel Chain: read-only contract call.
    FeistelQuery {
        #[arg(long)]
        contract: String,
        #[arg(long)]
        method: String,
        #[arg(long, default_value = "")]
        input: String,
    },
    /// Feistel Chain: show a transaction's receipt.
    FeistelReceipt {
        #[arg(long)]
        txid: String,
    },
    /// Hamming Chain: post a blob (data availability).
    HammingPost {
        #[arg(long)]
        key: PathBuf,
        /// Up to 8 bytes, e.g. a rollup name.
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Hamming Chain: light-client availability check by random sampling.
    HammingSample {
        #[arg(long)]
        height: u64,
        #[arg(long, default_value_t = 0)]
        index: usize,
        #[arg(long, default_value_t = 16)]
        samples: u32,
    },
    /// Hamming Chain: rebuild a blob from a random half of its shards.
    HammingGet {
        #[arg(long)]
        height: u64,
        #[arg(long, default_value_t = 0)]
        index: usize,
        #[arg(long)]
        out: PathBuf,
    },
    /// Playfair bridge (run by each validator): approve registering another
    /// network at a Kerckhoffs height. Prints the approval as hex.
    BridgeApprove {
        /// This validator's node key.
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        remote: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        k_height: u64,
    },
    /// Playfair bridge: start tracking another network. Needs approvals from
    /// more than 2/3 of this network's validator stake (see bridge-approve).
    BridgeRegister {
        #[arg(long)]
        key: PathBuf,
        /// RPC of a node on the other network.
        #[arg(long)]
        remote: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        k_height: u64,
        /// Approval hex from bridge-approve (repeat for each validator).
        #[arg(long = "approval")]
        approvals: Vec<String>,
    },
    /// Playfair bridge: bring this network's light client of `remote` up to date.
    BridgeSync {
        #[arg(long)]
        remote: String,
    },
    /// Playfair bridge: send tokens to another network.
    BridgeSend {
        #[arg(long)]
        key: PathBuf,
        /// Destination network id (hex).
        #[arg(long)]
        dest_network: String,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        amount: u64,
        /// Send tokens wrapped from this origin network back home (hex).
        #[arg(long)]
        wrapped_origin: Option<String>,
    },
    /// Playfair bridge: deliver messages `remote` sent to this network.
    BridgeRelay {
        #[arg(long)]
        remote: String,
    },
    /// Start a validator's exit (signed by its cold withdrawal key).
    Exit {
        /// Withdrawal key file of the validator.
        #[arg(long)]
        withdrawal_key: PathBuf,
        /// Validator node id (pq1...).
        #[arg(long)]
        node: String,
    },
    /// Create a new asset on the Atbash Chain.
    CreateAsset {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        supply: u64,
    },
}

fn write_json<T: serde::Serialize>(path: &Path, v: &T) -> Result<(), String> {
    std::fs::write(path, serde_json::to_string_pretty(v).map_err(|e| e.to_string())?)
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn new_key(path: &Path) -> Result<Keypair, String> {
    let k = Keypair::generate();
    node::save_key(path, &k)?;
    Ok(k)
}

#[allow(clippy::too_many_arguments)]
fn testnet_init(
    dir: &Path,
    validators: usize,
    full_nodes: usize,
    p2p: u16,
    rpc: u16,
    stake: u64,
    faucet: u64,
) -> Result<(), String> {
    if dir.exists() {
        return Err(format!("{} already exists; remove it first", dir.display()));
    }
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let faucet_key = new_key(&dir.join("faucet.key"))?;
    let mut gvals = Vec::new();
    let names: Vec<String> = (0..validators)
        .map(|i| format!("validator-{i}"))
        .chain((0..full_nodes).map(|i| format!("full-{i}")))
        .collect();
    for (i, name) in names.iter().enumerate() {
        let nd = dir.join(name);
        std::fs::create_dir_all(&nd).map_err(|e| e.to_string())?;
        let k = new_key(&nd.join("node.key"))?;
        if i < validators {
            // Cold withdrawal key: hash-based SLH-DSA, kept offline.
            let cold = Keypair::generate_slh();
            node::save_key(&nd.join("withdrawal.key"), &cold)?;
            gvals.push(GenesisValidatorEntry {
                signing_key: hex::encode(&k.public.bytes),
                withdrawal: cold.address().to_text(),
                stake,
            });
        }
        // Every node bootstraps from validator-0 only; peer discovery finds the rest.
        let dial = usize::from(i > 0);
        let cfg = NodeConfig {
            name: name.clone(),
            key: "node.key".into(),
            genesis: "../genesis.json".into(),
            data_dir: "data".into(),
            listen: format!("127.0.0.1:{}", p2p as usize + i),
            rpc: format!("127.0.0.1:{}", rpc as usize + i),
            peers: (0..dial).map(|j| format!("127.0.0.1:{}", p2p as usize + j)).collect(),
            advertise: None,
        };
        write_json(&nd.join("config.json"), &cfg)?;
    }
    let genesis = Genesis {
        network: "pqchain-local-testnet".into(),
        validators: gvals,
        allocations: vec![Allocation { address: faucet_key.address().to_text(), amount: faucet }],
        consensus: node::ConsensusParams::default(),
    };
    write_json(&dir.join("genesis.json"), &genesis)?;
    println!("testnet created in {}", dir.display());
    println!("  network id   {}", hex::encode(genesis.network_id()?));
    println!("  faucet       {} ({faucet} native) key: {}", faucet_key.address().to_text(), dir.join("faucet.key").display());
    for (i, n) in names.iter().enumerate() {
        println!("  {n:<12} p2p 127.0.0.1:{}  rpc http://127.0.0.1:{}", p2p as usize + i, rpc as usize + i);
    }
    println!("start each node with: pqchain node --config {}/<name>/config.json", dir.display());
    Ok(())
}

fn print_balance(c: &Client, a: &Address) -> Result<(), String> {
    println!("{}", a.to_text());
    for chain in ["atbash", "kerckhoffs"] {
        let v = c.get(&format!("/balance/{chain}/{}", a.to_text()))?;
        println!("  {chain:<11} {}  pending import: {}", v["assets"], v["pending_import"]);
    }
    Ok(())
}

fn submit(c: &Client, tx: pqchain::codec::Tx) -> Result<(), String> {
    let r = c.submit(&tx)?;
    println!("submitted {} tx {}", r["chain"].as_str().unwrap_or("?"), r["txid"].as_str().unwrap_or("?"));
    Ok(())
}

fn wallet_cmd(rpc: &str, cmd: WalletCmd) -> Result<(), String> {
    let c = Client::new(rpc);
    match cmd {
        WalletCmd::New { out, cold } => {
            let k = if cold { Keypair::generate_slh() } else { Keypair::generate() };
            node::save_key(&out, &k)?;
            println!("{}  {} (saved to {})", k.address().to_text(), pqchain::crypto::alg_name(k.alg()), out.display());
        }
        WalletCmd::CreateZone { key, name, members } => {
            let k = node::load_key(&key)?;
            let members = members.iter().map(|m| Address::from_text(m)).collect::<Result<Vec<_>, _>>()?;
            submit(&c, wallet::create_zone(&c, &k, &name, members)?)?;
        }
        WalletCmd::RelayImport { key, chain } => {
            let k = node::load_key(&key)?;
            let (tx, amount) = wallet::relay_import(&c, &k, chain_from_str(&chain)?)?;
            println!("claiming {amount} (proofs verified by the receiving chain)");
            submit(&c, tx)?;
        }
        WalletCmd::ClaimRewards { key } => {
            let k = node::load_key(&key)?;
            let (tx, amount) = wallet::claim_rewards(&c, &k)?;
            println!("claiming {amount} in staking rewards");
            submit(&c, tx)?;
        }
        WalletCmd::FeistelImport { key } => {
            let k = node::load_key(&key)?;
            let (tx, amount) = wallet::feistel_import(&c, &k)?;
            println!("importing {amount} into the Feistel Chain");
            submit(&c, tx)?;
        }
        WalletCmd::FeistelExport { key, amount } => {
            let k = node::load_key(&key)?;
            submit(&c, wallet::feistel(&c, &k, 0, Action::Export { amount })?)?;
        }
        WalletCmd::FeistelDeploy { key, code, fuel } => {
            let k = node::load_key(&key)?;
            let bytes = std::fs::read(&code).map_err(|e| format!("{}: {e}", code.display()))?;
            let wasm = wat::parse_bytes(&bytes).map_err(|e| e.to_string())?.into_owned();
            let tx = wallet::feistel(&c, &k, fuel, Action::Deploy { code: wasm })?;
            if let pqchain::codec::Tx::Feistel(t) = &tx {
                println!("contract address {}", pqchain::feistel::contract_address(&k.address(), t.nonce).to_text());
            }
            submit(&c, tx)?;
        }
        WalletCmd::FeistelCall { key, contract, method, input, value, fuel } => {
            let k = node::load_key(&key)?;
            let input = hex::decode(&input).map_err(|e| e.to_string())?;
            let action = Action::Call { contract: Address::from_text(&contract)?, method, input, value };
            submit(&c, wallet::feistel(&c, &k, fuel, action)?)?;
        }
        WalletCmd::FeistelQuery { contract, method, input } => {
            let url = format!("{rpc}/feistel/query/{contract}/{method}");
            let reply = ureq::post(&url).send_string(&input).map_err(|e| e.to_string())?;
            println!("{}", reply.into_string().map_err(|e| e.to_string())?);
        }
        WalletCmd::FeistelReceipt { txid } => println!("{}", c.get(&format!("/feistel/receipt/{txid}"))?),
        WalletCmd::HammingPost { key, namespace, file } => {
            let k = node::load_key(&key)?;
            let data = std::fs::read(&file).map_err(|e| format!("{}: {e}", file.display()))?;
            let tx = wallet::hamming_post(&c, &k, &namespace, data)?;
            if let pqchain::codec::Tx::Hamming(t) = &tx {
                println!(
                    "blob: {} bytes -> {} shards ({} data + {} parity), commitment {}",
                    t.data.len(), t.commitment.shards(), t.commitment.k, t.commitment.k, hex::encode(&t.commitment.root[..8])
                );
            }
            submit(&c, tx)?;
        }
        WalletCmd::HammingSample { height, index, samples } => {
            let (cm, picked) = wallet::hamming_sample(&c, height, index, samples)?;
            println!("blob included in finalized Hamming block #{height} (certificate checked)");
            println!("sampled shards {picked:?} of {}: all verified", cm.shards());
            println!("probability the blob is unavailable: < {:.1e}", pqchain::hamming::miss_probability(samples));
        }
        WalletCmd::HammingGet { height, index, out } => {
            let (data, used) = wallet::hamming_get(&c, height, index)?;
            std::fs::write(&out, &data).map_err(|e| e.to_string())?;
            println!("rebuilt {} bytes from shards {used:?} -> {}", data.len(), out.display());
        }
        WalletCmd::BridgeApprove { key, remote, name, k_height } => {
            println!("{}", wallet::bridge_approve(&Client::new(&remote), &node::load_key(&key)?, &name, k_height)?);
        }
        WalletCmd::BridgeRegister { key, remote, name, k_height, approvals } => {
            let k = node::load_key(&key)?;
            let (tx, rid) = wallet::bridge_register(&c, &Client::new(&remote), &k, &name, k_height, &approvals)?;
            println!("registering network {} as '{name}'", hex::encode(rid));
            submit(&c, tx)?;
        }
        WalletCmd::BridgeSync { remote } => {
            let txs = wallet::bridge_sync(&c, &Client::new(&remote))?;
            println!("{} light-client update(s)", txs.len());
            for tx in txs {
                submit(&c, tx)?;
            }
        }
        WalletCmd::BridgeSend { key, dest_network, recipient, amount, wrapped_origin } => {
            let k = node::load_key(&key)?;
            let h = |s: &str| -> Result<[u8; 32], String> {
                hex::decode(s).ok().and_then(|b| b.try_into().ok()).ok_or("expected 32-byte hex".into())
            };
            let origin = wrapped_origin.as_deref().map(h).transpose()?;
            submit(&c, wallet::bridge_send(&c, &k, h(&dest_network)?, Address::from_text(&recipient)?, amount, origin)?)?;
        }
        WalletCmd::BridgeRelay { remote } => {
            for (tx, amount) in wallet::bridge_relay(&c, &Client::new(&remote))? {
                match c.submit(&tx) {
                    Ok(r) => println!("delivered {amount}: tx {}", r["txid"].as_str().unwrap_or("?")),
                    Err(e) if e.contains("already received") => {}
                    Err(e) => println!("skipped: {e}"),
                }
            }
        }
        WalletCmd::Exit { withdrawal_key, node } => {
            let k = node::load_key(&withdrawal_key)?;
            submit(&c, wallet::exit(Address::from_text(&node)?, &k))?;
        }
        WalletCmd::EncryptKey { key } => {
            let pass = std::env::var(node::PASSPHRASE_ENV).ok().filter(|p| !p.is_empty())
                .ok_or(format!("set {} to the new passphrase", node::PASSPHRASE_ENV))?;
            if node::key_is_encrypted(&key)? {
                return Err("key file is already encrypted".into());
            }
            let k = node::load_key_with(&key, None)?;
            node::save_key_with(&key, &k, Some(&pass), true)?;
            println!("{} encrypted (Argon2id + ChaCha20-Poly1305)", key.display());
        }
        WalletCmd::Show { key } => println!("{}", node::load_key(&key)?.address().to_text()),
        WalletCmd::Balance { key, address } => {
            let a = match (key, address) {
                (Some(k), _) => node::load_key(&k)?.address(),
                (None, Some(a)) => Address::from_text(&a)?,
                _ => return Err("pass --key or --address".into()),
            };
            print_balance(&c, &a)?;
        }
        WalletCmd::Send { key, to, amount, chain } => {
            let k = node::load_key(&key)?;
            submit(&c, wallet::send(&c, &k, chain_from_str(&chain)?, Address::from_text(&to)?, amount)?)?;
        }
        WalletCmd::Export { key, amount, from, to } => {
            let k = node::load_key(&key)?;
            submit(&c, wallet::export(&c, &k, chain_from_str(&from)?, chain_from_str(&to)?, amount)?)?;
        }
        WalletCmd::Import { key, chain } => {
            let k = node::load_key(&key)?;
            submit(&c, wallet::import(&c, &k, chain_from_str(&chain)?)?)?;
        }
        WalletCmd::Stake { key, node_key, amount } => {
            let k = node::load_key(&key)?;
            let nk: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(&node_key).map_err(|e| format!("{}: {e}", node_key.display()))?,
            )
            .map_err(|e| e.to_string())?;
            let pk = PublicKey {
                alg: ALG_ML_DSA_65,
                bytes: hex::decode(nk["public_key"].as_str().ok_or("node key has no public_key")?)
                    .map_err(|e| e.to_string())?,
            };
            println!("new validator node id {}", pk.address().to_text());
            submit(&c, wallet::stake(&c, &k, pk, amount)?)?;
        }
        WalletCmd::Delegate { key, node, amount } => {
            let k = node::load_key(&key)?;
            submit(&c, wallet::delegate(&c, &k, Address::from_text(&node)?, amount)?)?;
        }
        WalletCmd::CreateAsset { key, name, supply } => {
            let k = node::load_key(&key)?;
            let (tx, id) = wallet::create_asset(&c, &k, &name, supply)?;
            println!("asset {name} id {}", hex::encode(id));
            submit(&c, tx)?;
        }
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Demo => demo::run(),
        Cmd::TestnetInit { dir, validators, full_nodes, p2p_port, rpc_port, stake, faucet } => {
            testnet_init(&dir, validators, full_nodes, p2p_port, rpc_port, stake, faucet)
        }
        Cmd::Node { config } => tokio::runtime::Runtime::new()
            .map_err(|e| e.to_string())
            .and_then(|rt| rt.block_on(node::run(&config))),
        Cmd::Wallet { rpc, cmd } => wallet_cmd(&rpc, cmd),
    };
    if let Err(e) = r {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
