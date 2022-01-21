use pathfinder_lib::state::merkle_tree::{MerkleTree, NodeStorage};
use rusqlite::Connection;
use stark_hash::{stark_hash, StarkHash};
use std::io::{BufRead, Write};
use web3::types::U256;

const ZERO_HASH: StarkHash = StarkHash::ZERO;

fn main() {
    let mut args = std::env::args().fuse();

    let name = args.next().expect("unsupported environment");
    let choice = args.next();
    let mut choice = choice.as_deref();
    let extra = args.next();

    if extra.is_some() {
        choice = None;
    }

    let parse_and_push = if choice == Some("global") {
        parse_and_push_global
    } else if choice == Some("storage") {
        parse_and_push_storage
    } else {
        if let Some(other) = choice {
            eprintln!(
                r#"Argument needs to be "storage" or "global", not {:?}"#,
                other
            );
        } else if extra.is_some() {
            eprintln!(r"Too many arguments");
        } else {
            eprintln!(
                r#"USAGE:
- echo "1 2 3" | cargo run -p tree_tool --bin {0} global
- echo "1 2" | cargo run -p tree_tool --bin {0} storage"#,
                name
            );
        }
        std::process::exit(1);
    };

    let mut conn = Connection::open_in_memory().unwrap();

    // quick hack to see if committing every row works
    let commit_every = false;

    let root = {
        let transaction = conn.transaction().unwrap();

        let mut uut = MerkleTree::load("test".to_string(), &transaction, ZERO_HASH).unwrap();

        let mut buffer = String::new();
        let stdin = std::io::stdin();
        let mut stdin = stdin.lock();

        let mut first = true;
        let mut stdout = std::io::stdout();

        loop {
            buffer.clear();
            let read = stdin.read_line(&mut buffer).unwrap();

            if read == 0 {
                break;
            }

            let buffer = buffer.trim();
            if buffer.is_empty() || buffer.chars().next() == Some('#') {
                // allow comments and empty lines for clearer examples
                continue;
            }

            if commit_every && !first {
                let root = uut.commit().unwrap();
                uut = MerkleTree::load("test".to_string(), &transaction, root).unwrap();
                print!(".");
                stdout.flush().unwrap();
            }

            if first {
                first = false;
            }

            parse_and_push(buffer, &mut uut);
        }

        let root = uut.commit().unwrap();

        if commit_every {
            println!(".");
        }

        transaction.commit().unwrap();
        root
    };

    println!("{:?}", Hex(root.as_ref()));

    let tx = conn.transaction().unwrap();
    let mut stmt = tx.prepare("select hash, data from test").unwrap();
    let mut res = stmt.query([]).unwrap();

    while let Some(row) = res.next().unwrap() {
        let hash = row.get_ref(0).unwrap().as_blob().unwrap();
        let data = row.get_ref(1).unwrap().as_blob().unwrap();

        if data.is_empty() {
            // this is a starknet_storage_leaf, and currently we don't have the contract state
            continue;
        }

        eprintln!("patricia_node:{:?} => {:?}", Hex(hash), Hex(data));
    }
}

fn parse_and_push_global<T>(buffer: &str, uut: &mut MerkleTree<T>)
where
    T: NodeStorage,
{
    let (contract_address, buffer) = buffer
        .split_once(' ')
        .expect("expected 3 values, whitespace separated; couldn't find first space");

    let contract_address = parse(contract_address)
        .unwrap_or_else(|| panic!("invalid contract_address: {:?}", contract_address));

    let buffer = buffer.trim();
    let (contract_hash, buffer) = buffer
        .split_once(' ')
        .expect("expected 3 values, whitespace separated; couldn't find second space");

    let contract_hash = parse(contract_hash)
        .unwrap_or_else(|| panic!("invalid contract_hash: {:?}", contract_hash));

    let contract_commitment_root = buffer.trim();
    let contract_commitment_root =
        parse(contract_commitment_root).unwrap_or_else(|| panic!("invalid value: {:?}", buffer));

    let value = stark_hash(contract_hash, contract_commitment_root);
    let value = stark_hash(value, ZERO_HASH);
    let value = stark_hash(value, ZERO_HASH);

    // python side does make sure every key is unique before asking the tree code to
    // process it
    uut.set(contract_address, value)
        .expect("how could this fail?");
}

fn parse_and_push_storage<T>(buffer: &str, uut: &mut MerkleTree<T>)
where
    T: NodeStorage,
{
    // here we read just address = value
    // but there's no such thing as splitting whitespace \s+ which I think is what the
    // python side is doing so lets do it like this for a close approximation

    let (address, buffer) = buffer.split_once(' ').expect("expected 2 values per line");

    let address = parse(address).unwrap_or_else(|| panic!("invalid address: {:?}", address));

    let buffer = buffer.trim();
    let value = parse(buffer).unwrap_or_else(|| panic!("invalid value: {:?}", buffer));

    uut.set(address, value).expect("how could this fail?");
}

fn parse(s: &str) -> Option<StarkHash> {
    if let Some(suffix) = s.strip_prefix("0x") {
        StarkHash::from_hex_str(suffix).ok()
    } else {
        let u = U256::from_dec_str(s).ok()?;
        let mut bytes = [0u8; 32];
        u.to_big_endian(&mut bytes);
        StarkHash::from_be_bytes(bytes).ok()
    }
}

struct Hex<'a>(&'a [u8]);

use std::fmt;

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|&b| write!(f, "{:02x}", b))
    }
}
