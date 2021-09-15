import json
from collections import Counter, defaultdict
import numpy as np

def parse_logs(file_name):
    events = []
    with open(file_name) as f:
        lines = [line for line in f.readlines() if 'Profiler' in line]
        for line in lines:
            s = line.split("Profiler: ")
            data = json.loads(s[1])
            events.append(data)

    return events

def process_events(events):
    costs = []
    block_stats = []
    insert_events = {}
    for event in events:
        name = event["event"]
        if name == "Inserting new bitcoin header":
            insert_events[event["details"]["new_burn_height"]] = event
        elif name == "Finished running tenure":
            last_burn_height = event["details"]["last_burn_height"]
            last_insert_at_height = insert_events[last_burn_height]
            if last_insert_at_height:
                block_stats.append(BlockProduction(
                    last_insert_at_height["details"]["timestamp"],
                    event["details"]["timestamp"],
                    last_burn_height,
                    event["details"]["is_good_commitment_opt"]
                ))
        elif name == "Execution cost of processed transaction":
            costs.append(ExecutionCost(
                event["details"]["runtime"],
                event["details"]["read_count"],
                event["details"]["read_length"],
                event["details"]["write_count"],
                event["details"]["write_length"],
            ))

    return (block_stats, costs)



### Analysis
# Q1, Q2
class BlockProduction:
    def __init__(self, start_time, end_time, height, is_good_commitment):
        self.start_time = start_time
        self.end_time = end_time
        self.height = height
        self.is_good_commitment = is_good_commitment

# data - list of BlockProduction stats
#   --> a data point should be produced every time a block commitment is produced (so when the log line is created at
#       the end of RunTenure
#   --> there can be multiple end_times for the same start_time
#   --> some start_times may not be associated with any end_time (for example, for the blocks downloaded during ibd)
# canonical_chain - map of height to BHH of canonical chain
# QUESTION: how to get the canonical block chain?
def compute_q1(data):
    fastest_block_tracker = {}
    good_block_tracker = {}

    for block_data in data:
        block_prod_time = block_data.end_time - block_data.start_time
        if block_data.height not in fastest_block_tracker or block_prod_time < fastest_block_tracker[block_data.height]:
            fastest_block_tracker[block_data.height] = block_prod_time

        if block_data.is_good_commitment and (block_data.height not in good_block_tracker or block_prod_time < good_block_tracker[block_data.height]):
            good_block_tracker[block_data.height] = block_prod_time


    # Q1
    print("Answering Q1: What is the average time a synchronized miner takes to broadcast a block commitment?")
    avg = 0
    num_values = len(fastest_block_tracker)
    for (_height, time) in fastest_block_tracker.items():
        avg += time/num_values
    print("Average: ", avg, "\n")

    # Q2
    print("Answering Q2: What is the average time a synchronized miner takes to broadcast their first good block commitment?")
    avg = 0
    num_values = len(good_block_tracker)
    for (_height, time) in good_block_tracker.items():
        avg += time/num_values
    print("Average: ", avg, "\n")

# Test for Q1/ Q2
# test case:
#     dummy_block_data = [BlockProduction(2, 5, 2, false), BlockProduction(2, 3, 2, false), BlockProduction(2, 6, 2, true)]
#     compute_q1(dummy_block_data, dummy_can_chain)
# expected ans:
#     Answering Q1: What is the average time a synchronized miner takes to broadcast a block commitment?
#     Average:  1.0
#     Answering Q2: What is the average time a synchronized miner takes to broadcast their first good block commitment?
#     Average:  4.0

# test case:
#     dummy_block_data = [BlockProduction(2, 5, 2, False), BlockProduction(2, 3, 2, False), BlockProduction(2, 6, 2, True),
#                         BlockProduction(10, 12, 3, False), BlockProduction(10, 13, 3, True), BlockProduction(10, 12, 3, True)]
#     compute_q1(dummy_block_data)
# expected ans:
#     Answering Q1: What is the average time a synchronized miner takes to broadcast a block commitment?
#     Average:  1.5
#     Answering Q2: What is the average time a synchronized miner takes to broadcast their first good block commitment?
#     Average:  3.0

# Q3
# data - list of maps
# each map's keys are the 5 cost dimensions, the value is the percent of the block budget consumed.
def compute_q3(data):
    counter = Counter()
    for cost_percent_map in data:
        max_dim = max(cost_percent_map, key=cost_percent_map.get)
        counter[max_dim] += 1

    print("Answering Q3: Determine distribution of transactions limited by each cost dimension.")
    total = sum(counter.values())
    for k in counter:
        counter[k] = counter[k]*100/total
        print(k,  counter[k])
    return counter

# test case:
#     dummy_data = [{"read_count": 34, "read_length": 10, "write_count": 10, "write_length": 13, "runtime": 32},
#                   {"read_count": 43, "read_length": 10, "write_count": 10, "write_length": 25, "runtime": 32},
#                   {"read_count": 16, "read_length": 10, "write_count": 55, "write_length": 17, "runtime": 32},
#                   {"read_count": 12, "read_length": 33, "write_count": 10, "write_length": 22, "runtime": 32},
#                   {"read_count": 19, "read_length": 39, "write_count": 9, "write_length": 27, "runtime": 32}]
# expected answer
#     compute_q3(dummy_data)

class ExecutionCost:
    def __init__(self, runtime, read_count, read_length, write_count, write_length):
        self.runtime = runtime
        self.read_count = read_count
        self.read_length = read_length
        self.write_count = write_count
        self.write_length = write_length

    # limit also should have type ExecutionCost
    # TODO: alter definition of what it means to exceed limit
    def limit_exceeded(self, limit):
        if self.runtime > limit.runtime:
            return True, "runtime"
        if self.read_count > limit.read_count:
            return True, "read_count"
        if self.read_length > limit.read_length:
            return True, "read_length"
        if self.write_count > limit.write_count:
            return True, "write_count"
        if self.write_length > limit.write_length:
            return True, "write_length"

        return False, ""

class BlockTxData:
    def __init__(self, stacks_block_id, block_cost_limit, event_frequency_map, contract_call_frequency_map, anchored_block_cost, microblocks_cost):
        self.stacks_block_id = stacks_block_id
        self.block_cost_limit = block_cost_limit # type ExecutionCost
        self.event_frequency_map = event_frequency_map # map of event name to count
        self.contract_call_frequency_map = contract_call_frequency_map # map of tuple (issuer, name) to count
        self.anchored_block_cost = anchored_block_cost
        self.microblocks_cost = microblocks_cost

# block_limit = ExecutionCost(10, 10, 10, 10, 10)
# under_limit_cost = ExecutionCost(1, 0, 10, 8, 7)
# data = { 1: BlockTxData("abc", block_limit, ),
#          2: BlockTxData(),
#          }

# log data: Profiler Q3: frequencies of all events for a block,
# stacks_block_id: d2b495b167ca2c1917bc100fe25e4af93ff29f4bcdbd85f50e7d587cd79eca5f,
# event_frequency_map: "stx_lock_event": 2; "stx_transfer_event": 4; "contract_event": 2; ,
# contract_call_frequency_map: QualifiedContractIdentifier { issuer: StandardPrincipalData(SP3FBR2AGK5H9QBDH3EEN6DF8EK8JY7RX8QJ5SVTE), name: ContractName("send-many-memo") }: 2; ,
# block_cost_limit: {"runtime": 5000000000, "write_len": 15000000, "write_cnt": 7750, "read_len": 100000000, "read_cnt": 7750},
# anchored_block_cost: {"runtime": 0, "write_len": 0, "write_cnt": 0, "read_len": 0, "read_cnt": 0},
# microblocks_cost: {"runtime": 191309000, "write_len": 1698, "write_cnt": 12, "read_len": 67066, "read_cnt": 49}

# block_tx_data - map of burn block height to BlockTxData
# analyze full blocks
def compute_q4(block_tx_data, verbose=False, min_burn_height=None):
    total_block_count = 0
    full_block_counter = 0
    full_block_limit_hit = defaultdict(int)
    full_block_contract_counter = defaultdict(int)
    full_block_num_contracts = []
    all_block_num_events = []
    all_block_event_counter = defaultdict(int)
    for burn_height, curr_block_data in block_tx_data.iteritems():
        # If min_burn_height is set, don't consider blocks with lesser heights
        if min_burn_height != None and burn_height < min_burn_height:
            continue

        total_block_count += 1
        # check if the block was full by comparing block_cost_limit with anchored_block_cost
        block_cost_limit = curr_block_data.block_cost_limit
        anchored_block_cost = curr_block_data.anchored_block_cost
        (limit_exceeded, limit_name) = anchored_block_cost.limit_exceeded(block_cost_limit)

        if limit_exceeded:
            # full block stats
            # - average number of contracts called in a full block
            # - total count of contracts called from full blocks
            # - percentages of which limit was hit in the block limit
            full_block_counter += 1
            full_block_limit_hit[limit_name] += 1

            if verbose:
                print("burn_height: ", burn_height, ", block_tx_data: ", block_tx_data)

            # compute stats
            contract_map = curr_block_data.contract_call_frequency_map
            total_calls = 0
            for contract_id, call_count in contract_map.iteritems():
                full_block_contract_counter[contract_id] += call_count
                total_calls += call_count

            full_block_num_contracts.append(total_calls)

        # normal stats
        # - avg number of total events
        # - total count of each event across all blocks
        total_event_count = 0
        for event_id, event_count in curr_block_data.event_frequency_map.iteritems():
            total_event_count += event_count
            all_block_event_counter[event_id] += event_count
        all_block_num_events.append(total_event_count)

    print("Answering Q4-a: stats on full blocks")
    print(full_block_counter, " out of ", total_block_count, " blocks were full. ", full_block_counter/total_block_count, "%.")
    avg_contracts_called =  np.average(np.asarray(full_block_num_contracts))
    print("Average contracts called:", avg_contracts_called)
    print("Total contract call counter:", full_block_contract_counter)
    percent_breakdown_limit = {}
    for cost_dim, num_hits in full_block_limit_hit.iteritems():
        percent_breakdown_limit[cost_dim] = num_hits/full_block_counter
    print("Percent breakdown of which cost limit was hit in a full block:", percent_breakdown_limit)


    print("Answering Q4-b: stats on all blocks")
    avg_events_per_block =  np.average(np.asarray(all_block_event_counter))
    print("Average number of events per block:", avg_events_per_block)
    print("Total event counter:", all_block_num_events)

events = parse_logs("sample_logs.txt")
block_stats, costs = process_events(events)

print(block_stats)
print(costs)
