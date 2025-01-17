use rusqlite::Transaction;

use crate::storage::schema::PostMigrationAction;

/// This schema migration creates a missing index that is used to join blocks
/// and transactions when we're querying for all transactions in a block.
///
/// According to load tests this improves block query performance significantly.
pub(crate) fn migrate(transaction: &Transaction) -> anyhow::Result<PostMigrationAction> {
    // Create the new index.
    transaction.execute(
        "CREATE INDEX starknet_transactions_block_hash ON starknet_transactions(block_hash)",
        [],
    )?;

    Ok(PostMigrationAction::None)
}
