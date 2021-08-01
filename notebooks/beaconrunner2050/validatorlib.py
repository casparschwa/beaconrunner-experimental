import time
from typing import Set, Optional, Sequence, Tuple, Dict, Text
from dataclasses import dataclass, field
import specs

from eth2spec.utils.ssz.ssz_impl import hash_tree_root
from eth2spec.utils.ssz.ssz_typing import Container, List, uint64, Bitlist, Bytes32

frequency = 1
assert frequency in [1, 10, 100, 1000] 

class ValidatorMove(object):
    # Used to record validator moves.
    time: uint64
    slot: specs.Slot
    move: str
        
    def __init__(self, time, slot, move):
        self.time = time
        self.slot = slot
        self.move = move
        
class ValidatorData:
    # We could add more things here, they are all the items that are useful to build
    # validator strategies (when/if to attest/propose etc.)
    slot: specs.Slot
    time_ms: uint64
    head_root: specs.Root
    current_epoch: specs.Epoch
    current_attest_slot: specs.Slot
    current_committee_index: specs.CommitteeIndex
    current_committee: List[specs.ValidatorIndex, specs.MAX_VALIDATORS_PER_COMMITTEE]
    next_attest_slot: specs.Slot
    next_committee_index: specs.CommitteeIndex
    next_committee: List[specs.ValidatorIndex, specs.MAX_VALIDATORS_PER_COMMITTEE]
    last_slot_attested: Optional[specs.Slot]
    current_proposer_duties: Sequence[bool]
    last_slot_proposed: Optional[specs.Slot]
    recorded_attestations: List[specs.Root, specs.VALIDATOR_REGISTRY_LIMIT]
    received_block: bool

class HashableStore(Container):
    # We cache a map from current state of the `Store` to `head`, since `get_head`
    # is computationally intensive. But `Store` is not hashable right off the bat.
    # `get_head` only depends on stored blocks and latest messages, so we use that here.
    recorded_attestations: List[specs.Root, specs.VALIDATOR_REGISTRY_LIMIT]
    recorded_blocks: List[specs.Root, specs.VALIDATOR_REGISTRY_LIMIT]
        
class BRValidator:
    validator_index: specs.ValidatorIndex
    store: specs.Store
    history: List[ValidatorMove, specs.VALIDATOR_REGISTRY_LIMIT]
    data: ValidatorData
        
    ### Static caches for expensive operations
    # head_store stores a map from store hash to head root
    head_store: Dict[specs.Root, specs.Root] = {}
    
    # state_store stores a map from (current_state_hash, to_slot) calling
    # process_slots(current_state, to_slot)
    state_store: Dict[Tuple[specs.Root, specs.Slot], specs.BeaconState] = {}

    def __init__(self, state, validator_index):
        # Validator constructor
        # We preload a bunch of things, to be updated later on as needed
        # The validator is initialised from some base state, and given a `validator_index`
        self.validator_index = validator_index
        
        self.store = specs.get_forkchoice_store(state)
        self.history = []
        
        self.data = ValidatorData()
        self.data.time_ms = self.store.time * 1000
        self.data.recorded_attestations = []
        
        self.data.slot = specs.get_current_slot(self.store)
        self.data.current_epoch = specs.compute_epoch_at_slot(self.data.slot)
        
        self.data.head_root = self.get_head()
        current_state = state.copy()
        if current_state.slot < self.data.slot:
            specs.process_slots(current_state, self.data.slot)
        
        # Initialize data.committee, data.committee_index, data.current_attest_slot, data.current_proposer_duties
        self.update_attester(current_state, self.data.current_epoch)
        self.update_proposer(current_state)
        self.update_data()
        
    def get_hashable_store(self):
        # Returns a hash of the current store state
        
        return HashableStore(
            recorded_attestations = self.data.recorded_attestations,
            recorded_blocks = list(self.store.blocks.keys())
        )
    
    def get_head(self):
        # Our cached reimplementation of `get_head`.
        
        store_root = hash_tree_root(self.get_hashable_store())
        
        # If we can get the head from the cache, great!
        if store_root in BRValidator.head_store:
            return BRValidator.head_store[store_root]
        
        # Otherwise we must compute it again :(
        else:
            head_root = specs.get_head(self.store)
            BRValidator.head_store[store_root] = head_root
            return head_root
    
    def process_to_slot(self, current_state_root, slot):
        # Our cached `process_slots` operation
        
        # If we want to fast-forward a state root to some slot, we check if we have already recorded the
        # resulting state.
        if (current_state_root, slot) in BRValidator.state_store:
            return BRValidator.state_store[(current_state_root, slot)].copy()
        
        # If we haven't, we need to process it.
        else:
            current_state = self.store.block_states[current_state_root].copy()
            if current_state.slot < slot:
                specs.process_slots(current_state, slot)
            BRValidator.state_store[(current_state_root, slot)] = current_state
            return current_state.copy()
        
    def update_time(self, frequency = frequency) -> None:
        # Moving validators' clocks by one step
        # To keep it simple, we assume frequency is a power of ten (see `assert` above)
        # frequency=1 implies we are moving in full seconds, frequency=10 implies we are moving in tenths of a second
        self.data.time_ms = self.data.time_ms + int(1000 / frequency)
        if self.data.time_ms % 1000 == 0:
            # The store is updated each second in the specs
            specs.on_tick(self.store, self.store.time + 1)
            
            # If a new slot starts, we update
            if specs.get_current_slot(self.store) != self.data.slot:
                self.update_data()
                
    def forward_by(self, seconds, frequency = frequency) -> None:
        # A utility method to forward the clock by a given number of seconds.
        # Useful for explanations!
        
        # Depending on the frequency we need to call update_time multiple times. 
        number_ticks = seconds * frequency
        for i in range(number_ticks):
            self.update_time(frequency)
    
    def update_attester(self, current_state, epoch):
        # This is a fairly expensive operation, so we try not to call it when we don't have to.
        # Update attester duties for the `epoch`.
        # This can be queried no earlier than two epochs before
        # (e.g., learn about epoch e + 2 duties at epoch t)
        
        current_epoch = specs.get_current_epoch(current_state)
        
        # When is the validator scheduled to attest in `epoch`?
        (committee, committee_index, attest_slot) = specs.get_committee_assignment(
            current_state,
            epoch,
            self.validator_index)
        if epoch == current_epoch:
            self.data.current_attest_slot = attest_slot
            self.data.current_committee_index = committee_index
            self.data.current_committee = committee
        elif epoch == current_epoch + 1:
            self.data.next_attest_slot = attest_slot
            self.data.next_committee_index = committee_index
            self.data.next_committee = committee
    
    def update_proposer(self, current_state):
        # This is a fairly expensive operation, so we try not to call it when we don't have to.
        # Update proposer duties for the current epoch.
        # We need to check for each slot of the epoch whether the validator is a proposer or not.
        
        current_epoch = specs.get_current_epoch(current_state)
        
        start_slot = specs.compute_start_slot_at_epoch(current_epoch)
        
        start_state = current_state.copy() if start_slot == current_state.slot else \
        self.store.block_states[specs.get_block_root(current_state, current_epoch)].copy()
                            
        current_proposer_duties = []
        for slot in range(start_slot, start_slot + specs.SLOTS_PER_EPOCH):
            if slot < start_state.slot:
                current_proposer_duties += [False]
                continue
            
            if start_state.slot < slot:
                specs.process_slots(start_state, slot)
                
            current_proposer_duties += [specs.get_beacon_proposer_index(start_state) == self.validator_index]
                
        self.data.current_proposer_duties = current_proposer_duties
        
    def update_attest_move(self):
        # When was the last attestation?
        
        slots_attested = sorted([log.slot for log in self.history if log.move == "attest"], reverse = True)
        self.data.last_slot_attested = None if len(slots_attested) == 0 else slots_attested[0]
        
    def update_propose_move(self):
        # When was the last block proposal?
        
        slots_proposed = sorted([log.slot for log in self.history if log.move == "propose"], reverse = True)
        self.data.last_slot_proposed = None if len(slots_proposed) == 0 else slots_proposed[0]
    
    def update_data(self) -> None:            
        # The head may change if we recorded a new block/new attestation
        # Attester/proposer responsibilities may change if head changes *and*
        # canonical chain changes to further back from start current epoch
        #
        # ---x------
        #    \        x is fork point
        #     -----
        #
        # In the following attester = attester responsibilities for current epoch
        #                  proposer = proposer responsibilities for current epoch
        #
        # - If x after current epoch change (---|--x , | = start current epoch), proposer and attester don't change
        # - If x between start of previous epoch and start of current epoch (--||--x---|-- , || = start previous epoch)
        #   proposer changes but not attester
        # - If x before start of previous epoch (--x--||-----|----) both proposer and attester change
        
        slot = specs.get_current_slot(self.store)
        new_slot = self.data.slot != slot
    
        # Current epoch in validator view
        current_epoch = specs.compute_epoch_at_slot(slot)

        self.update_attest_move()
        self.update_propose_move()
                
        # Did the validator record a block for this slot?
        received_block = len([block for block_root, block in self.store.blocks.items() if block.slot == slot]) > 0
        
        if not new_slot:
            # It's not a new slot, we are here because a new block/attestation was received

            # Getting the current state, fast-forwarding from the head
            head_root = self.get_head()
            
            if self.data.head_root != head_root:
                # New head!
                lca = lowest_common_ancestor(
                    self.store, self.data.head_root, head_root)
                lca_epoch = specs.compute_epoch_at_slot(lca.slot)

                if lca_epoch == current_epoch:
                    # do nothing
                    pass
                else:
                    current_state = self.process_to_slot(head_root, slot)
                    if lca_epoch == current_epoch - 1:
                        self.update_proposer(current_state)
                    else:
                        self.update_proposer(current_state)
                        self.update_attester(current_state, current_epoch)
                self.data.head_root = head_root
                
        else:
            # It's a new slot. We should update our proposer/attester duties
            # if it's also a new epoch. If not we do nothing.
            if self.data.current_epoch != current_epoch:
                current_state = self.process_to_slot(self.data.head_root, slot)

                # We need to check our proposer role for this new epoch
                self.update_proposer(current_state)

                # We need to check our attester role for this new epoch
                self.update_attester(current_state, current_epoch)
                            
        self.data.slot = slot
        self.data.current_epoch = current_epoch
        self.data.received_block = received_block
                
    def log_block(self, item: specs.SignedBeaconBlock) -> None:
        # Recording our own "block proposal" move in our own history
        
        self.history.append(ValidatorMove(
            time = self.data.time_ms,
            slot = item.message.slot,
            move = "propose"
        ))
        self.update_propose_move()

    def log_attestation(self, item: specs.Attestation) -> None:
        # Recording our own "attestation proposal" move in our own history
        
        self.history.append(ValidatorMove(
            time = self.data.time_ms,
            slot = item.data.slot,
            move = "attest"
        ))
        self.update_attest_move()

    def record_block(self, item: specs.SignedBeaconBlock) -> bool:
        # When a validator receives a block from the network, they call `record_block` to see
        # whether they should record it.
        
#         print(self.validator_index, "maybe record block", hash_tree_root(item.message))
        
        # If we already know about the block, do nothing
        if hash_tree_root(item.message) in self.store.blocks:
            return False
        
        # Sometimes recording the block fails. Examples include:
        # - The block slot is not the current slot (we keep it in memory for later, when we check backlog)
        # - The block parent is not known
        try:
            state = self.process_to_slot(item.message.parent_root, item.message.slot)
            specs.on_block(self.store, item, state = state)
#             print(self.validator_index, "recorded block", str(hash_tree_root(item.message))[-6:], "->", str(item.message.parent_root)[-6:])
        except AssertionError as e:
            print(self.validator_index, "didn't record block", str(hash_tree_root(item.message))[-6:], "->", str(item.message.parent_root)[-6:])
            print(e.args)
            return False
        
        # If attestations are included in the block, we want to record them
        for attestation in item.message.body.attestations:
            self.record_attestation(attestation)
        
        return True

    def record_attestation(self, item: specs.Attestation) -> bool:
        # When a validator receives an attestation from the network, they call `record_attestation` to see
        # whether they should record it.
        
        att_hash = hash_tree_root(item)
        
        # If we have already seen this attestation, no need to go further
        if att_hash in self.data.recorded_attestations:
            return False
        
        # Sometimes recording the attestation fails. Examples include:
        # - The attestation is not for the current slot *PLUS ONE*
        #   (we keep it in memory for later, when we check backlog)
        # - The block root it is attesting for is not known
        try:
            specs.on_attestation(self.store, item)
            self.data.recorded_attestations += [att_hash]
            return True
        except:
            return False

    def check_backlog(self, known_items: Dict[str, Sequence[Container]]) -> None:
        # Called whenever a new event happens on the network that might make a validator update
        # their internals.
        # We loop over known blocks and attestations to check whether we should record any
        # that we might have discarded before, or just received.
        
        recorded_blocks = 0
        for block in known_items["blocks"]:
            recorded = self.record_block(block.item)
            if recorded:
                recorded_blocks += 1
        
        recorded_attestations = 0
        for attestation in known_items["attestations"]:
            recorded = self.record_attestation(attestation.item)
            if recorded:
                recorded_attestations += 1
        
        # If we do record anything, update the internals.
        if recorded_blocks > 0 or recorded_attestations > 0:
            self.update_data()

### Utilities            

def lowest_common_ancestor(store, old_head, new_head) -> Optional[specs.BeaconBlock]:
    # in most cases, old_head <- new_head
    # we sort of (loosely) optimise for this
    
    new_head_ancestors = [new_head]
    current_block = store.blocks[new_head]
    keep_searching = True
    while keep_searching:
        parent_root = current_block.parent_root
        parent_block = store.blocks[parent_root]
        if parent_root == old_head:
            return store.blocks[old_head]
        elif parent_block.slot == 0:
            keep_searching = False
        else:
            new_head_ancestors += [parent_root]
            current_block = parent_block
        
    # At this point, old_head wasn't an ancestor to new_head
    # We need to find old_head's ancestors
    current_block = store.blocks[old_head]
    keep_searching = True
    while keep_searching:
        parent_root = current_block.parent_root
        parent_block = store.blocks[parent_root]
        if parent_root in new_head_ancestors:
            return parent_block
        elif parent_block.slot == 0:
            return None
        else:
            current_block = parent_block
            
### Attestation strategies            
            
def honest_attest(validator, known_items):
    
    # Unpacking
    validator_index = validator.validator_index
    store = validator.store
    committee_slot = validator.data.current_attest_slot
    committee_index = validator.data.current_committee_index
    committee = validator.data.current_committee
    
    # What am I attesting for?
    block_root = validator.get_head()
    head_state = store.block_states[block_root].copy()
    if head_state.slot < committee_slot:
        specs.process_slots(head_state, committee_slot)
    start_slot = specs.compute_start_slot_at_epoch(specs.get_current_epoch(head_state))
    epoch_boundary_block_root = block_root if start_slot == head_state.slot else specs.get_block_root_at_slot(head_state, start_slot)
    tgt_checkpoint = specs.Checkpoint(epoch=specs.get_current_epoch(head_state), root=epoch_boundary_block_root)
    
    att_data = specs.AttestationData(
        index = committee_index,
        slot = committee_slot,
        beacon_block_root = block_root,
        source = head_state.current_justified_checkpoint,
        target = tgt_checkpoint
    )

    # Set aggregation bits to myself only
    committee_size = len(committee)
    index_in_committee = committee.index(validator_index)
    aggregation_bits = Bitlist[specs.MAX_VALIDATORS_PER_COMMITTEE](*([0] * committee_size))
    aggregation_bits[index_in_committee] = True # set the aggregation bit of the validator to True
    attestation = specs.Attestation(
        aggregation_bits=aggregation_bits,
        data=att_data
    )
    
#     print(validator.validator_index, "attests for slot", committee_slot)
    
    return attestation

### Aggregation helpers

def build_aggregate(attestations):
    # All attestations are from the same slot, committee index and vote for
    # same source, target and beacon block.
    if len(attestations) == 0:
        return []

    aggregation_bits = Bitlist[specs.MAX_VALIDATORS_PER_COMMITTEE](*([0] * len(attestations[0].aggregation_bits)))
    for attestation in attestations:
        validator_index_in_committee = attestation.aggregation_bits.index(1)
        aggregation_bits[validator_index_in_committee] = True

    return specs.Attestation(
        aggregation_bits=aggregation_bits,
        data=attestations[0].data
    )

def aggregate_attestations(attestations):
    # Take in a set of attestations
    # Output aggregated attestations
    hashes = set([hash_tree_root(att.data) for att in attestations])
    return [build_aggregate(
        [att for att in attestations if att_hash == hash_tree_root(att.data)]
    ) for att_hash in hashes]

### Proposal strategies

def should_process_attestation(state: specs.BeaconState, attestation: specs.Attestation) -> bool:
    try:
        specs.process_attestation(state.copy(), attestation)
        return True
    except:
        return False
    

def honest_propose(validator, known_items):
    # Honest block proposal, using the current LMD-GHOST head and all known attestations,
    # aggregated.
    
    slot = validator.data.slot
    head = validator.data.head_root
    
    processed_state = validator.process_to_slot(head, slot)
    
    attestations = [att for att in known_items["attestations"] if should_process_attestation(processed_state, att.item)]
    attestations = aggregate_attestations([att.item for att in attestations if slot <= att.item.data.slot + specs.SLOTS_PER_EPOCH])
    
    beacon_block_body = specs.BeaconBlockBody(
        attestations=attestations
    )

    beacon_block = specs.BeaconBlock(
        slot=slot,
        parent_root=head,
        body=beacon_block_body,
        proposer_index = validator.validator_index
    )
    
    specs.process_block(processed_state, beacon_block)
    state_root = hash_tree_root(processed_state)
    beacon_block.state_root = state_root
    
    signed_beacon_block = specs.SignedBeaconBlock(message=beacon_block)
    
    print(validator.validator_index, "proposes block for slot", slot)

    return signed_beacon_block