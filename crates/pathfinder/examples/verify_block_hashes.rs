use anyhow::Context;
use pathfinder_lib::{
    core::{SequencerAddress, StarknetBlockHash, StarknetBlockNumber},
    sequencer::reply::{Block, Status},
    state::block_hash::compute_block_hash,
    storage::{StarknetBlocksBlockId, StarknetBlocksTable, StarknetTransactionsTable, Storage},
};
use stark_hash::StarkHash;

fn main() -> anyhow::Result<()> {
    let database_path = std::env::args().skip(1).next().unwrap();
    let storage = Storage::migrate(database_path.into())?;
    let db = storage
        .connection()
        .context("Opening database connection")?;

    let mut parent_block_hash = StarknetBlockHash(StarkHash::ZERO);

    for block_number in 0u64..200000 {
        let block_id = StarknetBlocksBlockId::Number(StarknetBlockNumber(block_number));
        let block = StarknetBlocksTable::get(&db, block_id)?.unwrap();
        let transactions_and_receipts =
            StarknetTransactionsTable::get_transaction_data_for_block(&db, block_id)?;

        let block_hash = block.hash;
        let (transactions, receipts): (Vec<_>, Vec<_>) =
            transactions_and_receipts.into_iter().unzip();

        let mut block = Block {
            block_hash: Some(block.hash),
            block_number: Some(block.number),
            gas_price: Some(block.gas_price),
            parent_block_hash,
            sequencer_address: Some(block.sequencer_address),
            state_root: Some(block.root),
            status: Status::AcceptedOnL1,
            timestamp: block.timestamp,
            transaction_receipts: receipts,
            transactions,
        };
        parent_block_hash = block_hash;

        // try with the value in the block
        let computed_block_hash = compute_block_hash(&block)?;
        if computed_block_hash != block_hash {
            // try with zero
            block.sequencer_address = Some(SequencerAddress(StarkHash::ZERO));
            let computed_block_hash = compute_block_hash(&block)?;
            if computed_block_hash != block_hash {
                // try with the magic value
                block.sequencer_address = Some(SequencerAddress(
                    StarkHash::from_hex_str(
                        "0x46A89AE102987331D369645031B49C27738ED096F2789C24449966DA4C6DE6B",
                    )
                    .unwrap(),
                ));
                let computed_block_hash = compute_block_hash(&block)?;
                if computed_block_hash != block_hash {
                    println!(
                        "Block hash mismatch at block {} computed {:?} received {:?}",
                        block_number, computed_block_hash, block_hash
                    );
                }
                // let json = serde_json::to_string(&block).unwrap();
                // println!("{}", json);
            }
        }
    }

    Ok(())
}
