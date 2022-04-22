use anyhow::{Context, Error, Result};
use bitvec::prelude::BitView;
use stark_hash::{stark_hash, StarkHash};

use crate::core::{SequencerAddress, StarknetBlockHash};
use crate::sequencer::reply::{
    transaction::{Event, Receipt, Transaction},
    Block,
};
use crate::state::merkle_tree::MerkleTree;

pub fn compute_block_hash(block: &Block) -> Result<StarknetBlockHash> {
    let transaction_commitment = calculate_transaction_commitment(&block.transactions)?;
    let event_commitment = calculate_event_commitment(&block.transaction_receipts)?;

    anyhow::ensure!(block.block_number.is_some());
    let block_number = block.block_number.unwrap();
    anyhow::ensure!(block.state_root.is_some());
    let state_root = block.state_root.unwrap();

    let num_transactions: u64 = block.transactions.len().try_into()?;
    let num_events = number_of_events_in_block(block);
    let num_events: u64 = num_events.try_into()?;

    let sequencer_address = block
        .sequencer_address
        .unwrap_or(SequencerAddress(StarkHash::ZERO));

    let data = [
        // block number
        StarkHash::from_u64(block_number.0),
        // global state root
        state_root.0,
        // sequencer address
        sequencer_address.0,
        // block timestamp
        StarkHash::from_u64(block.timestamp.0),
        // number of transactions
        StarkHash::from_u64(num_transactions),
        // transaction commitment
        transaction_commitment,
        // number of events
        StarkHash::from_u64(num_events),
        // event commitment
        event_commitment,
        // reserved: protocol version
        StarkHash::ZERO,
        // reserved: extra data
        StarkHash::ZERO,
        // parent block hash
        block.parent_block_hash.0,
    ];

    let block_hash = stark_hash_of_array(data.into_iter());

    Ok(StarknetBlockHash(block_hash))
}

#[derive(Default)]
struct CommitmentTree {
    tree: MerkleTree<()>,
}

impl CommitmentTree {
    pub fn set(&mut self, index: u64, value: StarkHash) -> Result<()> {
        let key = index.to_be_bytes();
        self.tree.set(key.view_bits(), value)
    }

    pub fn commit(self) -> Result<StarkHash> {
        self.tree.commit()
    }
}

fn calculate_transaction_commitment(transactions: &[Transaction]) -> Result<StarkHash> {
    let mut tree = CommitmentTree::default();

    transactions
        .iter()
        .enumerate()
        .try_for_each(|(idx, tx)| {
            let idx: u64 = idx.try_into()?;
            let final_hash = calculate_transaction_hash_with_signature(tx);
            tree.set(idx, final_hash)?;
            Result::<_, Error>::Ok(())
        })
        .context("Failed to create transaction commitment tree")?;

    tree.commit()
}

fn calculate_transaction_hash_with_signature(tx: &Transaction) -> StarkHash {
    lazy_static::lazy_static!(
        static ref HASH_OF_EMPTY_LIST: StarkHash = stark_hash_of_array([].into_iter());
    );

    let signature_hash = match &tx.signature {
        None => *HASH_OF_EMPTY_LIST,
        Some(signatures) => stark_hash_of_array(signatures.iter().map(|e| e.0.to_owned())),
    };

    stark_hash(tx.transaction_hash.0, signature_hash)
}

fn calculate_event_commitment(transaction_receipts: &[Receipt]) -> Result<StarkHash> {
    let mut tree = CommitmentTree::default();

    transaction_receipts
        .iter()
        .flat_map(|receipt| receipt.events.iter())
        .enumerate()
        .try_for_each(|(idx, e)| {
            let idx: u64 = idx.try_into()?;
            let event_hash = calculate_event_hash(e);
            tree.set(idx, event_hash)?;
            Result::<_, Error>::Ok(())
        })
        .context("Failed to create event commitment tree")?;

    tree.commit()
}

fn calculate_event_hash(event: &Event) -> StarkHash {
    let keys_hash = stark_hash_of_array(event.keys.iter().map(|key| key.0));
    let data_hash = stark_hash_of_array(event.data.iter().map(|data| data.0));

    stark_hash_of_array([event.from_address.0, keys_hash, data_hash].into_iter())
}

fn stark_hash_of_array<T: Iterator<Item = StarkHash>>(elements: T) -> StarkHash {
    // the hash of an array of length n is defined as h(...h((h(0,a1),a2),...,an),n)
    let (count, hash) = elements.fold((0u64, StarkHash::ZERO), |(count, hash), x| {
        (count.checked_add(1).unwrap(), stark_hash(hash, x))
    });
    let count = StarkHash::from_u64(count);
    stark_hash(hash, count)
}

fn number_of_events_in_block(block: &Block) -> usize {
    block
        .transaction_receipts
        .iter()
        .flat_map(|r| r.events.iter())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hash_on_elements() {
        let elements = [
            StarkHash::from_hex_str("0x1").unwrap(),
            StarkHash::from_hex_str("0x2").unwrap(),
            StarkHash::from_hex_str("0x3").unwrap(),
            StarkHash::from_hex_str("0x4").unwrap(),
        ];

        // produced by the cairo-lang Python implementation:
        // `hex(compute_hash_on_elements([1, 2, 3, 4]))`
        let expected_hash = StarkHash::from_hex_str(
            "0x66bd4335902683054d08a0572747ea78ebd9e531536fb43125424ca9f902084",
        )
        .unwrap();
        let computed_hash = stark_hash_of_array(elements.into_iter());
        assert_eq!(expected_hash, computed_hash);
    }

    #[test]
    fn test_event_hash() {
        use crate::core::{ContractAddress, EventData, EventKey};

        let event = Event {
            from_address: ContractAddress::from_hex_str("0xdeadbeef").unwrap(),
            data: vec![
                EventData(StarkHash::from_hex_str("0x5").unwrap()),
                EventData(StarkHash::from_hex_str("0x6").unwrap()),
                EventData(StarkHash::from_hex_str("0x7").unwrap()),
                EventData(StarkHash::from_hex_str("0x8").unwrap()),
                EventData(StarkHash::from_hex_str("0x9").unwrap()),
            ],
            keys: vec![
                EventKey(StarkHash::from_hex_str("0x1").unwrap()),
                EventKey(StarkHash::from_hex_str("0x2").unwrap()),
                EventKey(StarkHash::from_hex_str("0x3").unwrap()),
                EventKey(StarkHash::from_hex_str("0x4").unwrap()),
            ],
        };

        // produced by the cairo-lang Python implementation:
        // `hex(calculate_event_hash(0xdeadbeef, [1, 2, 3, 4], [5, 6, 7, 8, 9]))`
        let expected_event_hash = StarkHash::from_hex_str(
            "0xdb96455b3a61f9139f7921667188d31d1e1d49fb60a1aa3dbf3756dbe3a9b4",
        )
        .unwrap();
        let calculated_event_hash = calculate_event_hash(&event);
        assert_eq!(expected_event_hash, calculated_event_hash);
    }

    #[test]
    fn test_final_transaction_hash() {
        use crate::core::{ContractAddress, StarknetTransactionHash, TransactionSignatureElem};
        use crate::sequencer::reply::transaction::Type;

        let transaction = Transaction {
            calldata: None,
            class_hash: None,
            constructor_calldata: None,
            contract_address: ContractAddress(StarkHash::ZERO),
            contract_address_salt: None,
            entry_point_type: None,
            entry_point_selector: None,
            max_fee: None,
            signature: Some(vec![
                TransactionSignatureElem(StarkHash::from_hex_str("0x2").unwrap()),
                TransactionSignatureElem(StarkHash::from_hex_str("0x3").unwrap()),
            ]),
            transaction_hash: StarknetTransactionHash(StarkHash::from_hex_str("0x1").unwrap()),
            r#type: Type::InvokeFunction,
        };

        // produced by the cairo-lang Python implementation:
        // `hex(calculate_single_tx_hash_with_signature(1, [2, 3], hash_function=pedersen_hash))`
        let expected_final_hash = StarkHash::from_hex_str(
            "0x259c3bd5a1951eafb2f41e0b783eab92cfe4e108b2b1f071e3736f06b909431",
        )
        .unwrap();
        let calculated_final_hash = calculate_transaction_hash_with_signature(&transaction);
        assert_eq!(expected_final_hash, calculated_final_hash);
    }

    #[test]
    fn test_commitment_merkle_tree() {
        let mut tree = CommitmentTree::default();

        for (idx, hash) in [1u64, 2, 3, 4].into_iter().enumerate() {
            let hash = StarkHash::from_u64(hash);
            let idx: u64 = idx.try_into().unwrap();
            tree.set(idx, hash).unwrap();
        }

        // produced by the cairo-lang Python implementation:
        // `hex(asyncio.run(calculate_patricia_root([1, 2, 3, 4], height=64, ffc=ffc))))`
        let expected_root_hash = StarkHash::from_hex_str(
            "0x1a0e579b6b444769e4626331230b5ae39bd880f47e703b73fa56bf77e52e461",
        )
        .unwrap();
        let computed_root_hash = tree.commit().unwrap();

        assert_eq!(expected_root_hash, computed_root_hash);
    }

    #[test]
    fn test_number_of_events_in_block() {
        use crate::sequencer::reply::Block;

        let json = include_bytes!("../../resources/block_156000.json");
        let block: Block = serde_json::from_slice(json).unwrap();

        // this expected value comes from processing the raw JSON and counting the number of events
        const EXPECTED_NUMBER_OF_EVENTS: usize = 55;
        assert_eq!(number_of_events_in_block(&block), EXPECTED_NUMBER_OF_EVENTS);
    }

    #[test]
    fn test_block_hash_without_sequencer_address() {
        use crate::sequencer::reply::Block;

        // FIXME: This tests with a pre-0.8.0 block where zero is used as the sequencer address.
        // We should update compute_block_hash() once we have sequencer addresses in the block.
        let json = include_bytes!("../../resources/block_73653.json");
        let block: Block = serde_json::from_slice(json).unwrap();

        let block_hash = compute_block_hash(&block).unwrap();
        assert_eq!(block.block_hash.unwrap(), block_hash);
    }

    #[test]
    fn test_block_hash_with_sequencer_address() {
        use crate::sequencer::reply::Block;

        // FIXME: This tests with a pre-0.8.0 block where zero is used as the sequencer address.
        // We should update compute_block_hash() once we have sequencer addresses in the block.
        let json = include_bytes!("../../resources/block_186109.json");
        let block: Block = serde_json::from_slice(json).unwrap();

        let block_hash = compute_block_hash(&block).unwrap();
        assert_eq!(block.block_hash.unwrap(), block_hash);
    }
}
