//! `pqchain` command-line tool: demo, testnet setup, node daemon, wallet.

#![forbid(unsafe_code)]

mod demo;

use clap::{Parser, Subcommand};
use pqchain::crypto::{Address, Keypair, PublicKey, ALG_ML_DSA_65};
use pqchain::node::{self, chain_from_str, Allocation, Genesis, GenesisValidatorEntry, NodeConfig};
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
        // Validator i dials validators 0..i; full nodes dial every validator.
        let dial = if i < validators { i } else { validators };
        let cfg = NodeConfig {
            name: name.clone(),
            key: "node.key".into(),
            genesis: "../genesis.json".into(),
            data_dir: "data".into(),
            listen: format!("127.0.0.1:{}", p2p as usize + i),
            rpc: format!("127.0.0.1:{}", rpc as usize + i),
            peers: (0..dial).map(|j| format!("127.0.0.1:{}", p2p as usize + j)).collect(),
        };
        write_json(&nd.join("config.json"), &cfg)?;
    }
    let genesis = Genesis {
        network: "pqchain-local-testnet".into(),
        validators: gvals,
        allocations: vec![Allocation { address: faucet_key.address().to_text(), amount: faucet }],
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
        WalletCmd::Exit { withdrawal_key, node } => {
            let k = node::load_key(&withdrawal_key)?;
            submit(&c, wallet::exit(Address::from_text(&node)?, &k))?;
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
