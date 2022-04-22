from distutils.command.build import build
import sys
import asyncio

from starkware.cairo.common.hash_state import compute_hash_on_elements
from starkware.cairo.lang.vm.crypto import pedersen_hash
from starkware.starknet.services.api.feeder_gateway.block_hash import (
    calculate_event_hash, calculate_single_tx_hash_with_signature, calculate_patricia_root)
from starkware.starknet.services.api.feeder_gateway.response_objects import \
    StarknetBlock
from starkware.starknet.services.api.feeder_gateway.block_hash import calculate_block_hash, calculate_event_hash
from starkware.storage.storage import FactFetchingContext
from starkware.storage.dict_storage import DictStorage
from starkware.python.utils import from_bytes, to_bytes
from starkware.starknet.definitions.general_config import default_general_config, build_general_config
from starkware.starknet.definitions.transaction_type import TransactionType


def main():

    print(hex(calculate_event_hash(0xdeadbeef, [1, 2, 3, 4], [5, 6, 7, 8, 9])))

    print(hex(compute_hash_on_elements([1, 2, 3, 4])))

    print(hex(calculate_single_tx_hash_with_signature(
        1, [2, 3], hash_function=pedersen_hash)))

    def bytes_hash_function(x: bytes, y: bytes) -> bytes:
        return to_bytes(pedersen_hash(from_bytes(x), from_bytes(y)))

    ffc = FactFetchingContext(storage=DictStorage(),
                              hash_func=bytes_hash_function)

    root = asyncio.run(calculate_patricia_root(
        [1, 2, 3, 4], height=64, ffc=ffc))
    print(hex(root))

    with open(sys.argv[1]) as f:
        general_config = build_general_config(default_general_config)
        block = StarknetBlock.loads(f.read())
        tx_hashes = [tx.transaction_hash for tx in block.transactions]
        tx_signatures = [tx.signature if tx.tx_type ==
                         TransactionType.INVOKE_FUNCTION else [] for tx in block.transactions]
        event_hashes = [
            calculate_event_hash(event.from_address, event.keys, event.data) for receipt in block.transaction_receipts for event in receipt.events]

        block_hash = asyncio.run(calculate_block_hash(general_config=general_config, parent_hash=block.parent_block_hash, block_number=block.block_number, global_state_root=block.state_root,
                                                      sequencer_address=block.sequencer_address, block_timestamp=block.timestamp, tx_hashes=tx_hashes, tx_signatures=tx_signatures, event_hashes=event_hashes))
        print(f"computed {block_hash} in block {block.block_hash}")


if __name__ == "__main__":
    main()
