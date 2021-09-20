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

def parse_execution_cost(input):
    ExecutionCost(
        input["runtime"],
        input["read_count"],
        input["read_length"],
        input["write_count"],
        input["write_length"],
    )

example = "QualifiedContractIdentifier { issuer: StandardPrincipalData(SP3FBR2AGK5H9QBDH3EEN6DF8EK8JY7RX8QJ5SVTE), name: ContractName(\"send-many-memo\") }: 4; QualifiedContractIdentifier { issuer: StandardPrincipalData(SP000000000000000000002Q6VF78), name: ContractName(\"bns\") }: 2; "
def parse_contract_call_frequency_map(input_str):
    contracts = list(filter(None, input_str.split("QualifiedContractIdentifier")))
    print(contracts)
# parse_contract_call_frequency_map(example)

def process_events(events):
    costs = []
    block_tenure_stats = []
    unmatched_block_tenure = []
    anchored_block_limit_hit = []
    microblock_limit_hit = []
    insert_events = {}
    block_tx_data = {}
    for event in events:
        name = event["event"]
        if name == "Inserting new bitcoin header":
            insert_events[event["details"]["new_burn_height"]] = event
        elif name == "Finished running tenure":
            last_burn_height = event["details"]["last_burn_height"]
            if last_burn_height not in insert_events:
                unmatched_block_tenure.append(last_burn_height)
            last_insert_at_height = insert_events[last_burn_height]
            is_good_commitment = None
            if event["details"]["is_good_commitment_opt"] != "none":
                is_good_commitment = event["details"]["is_good_commitment_opt"]
            if last_insert_at_height:
                block_tenure_stats.append(BlockProduction(
                    last_insert_at_height["details"]["timestamp"],
                    event["details"]["timestamp"],
                    last_burn_height,
                    is_good_commitment
                ))
        elif name == "Execution cost of processed transaction":
            costs.append(ExecutionCost(
                event["details"]["runtime"],
                event["details"]["read_count"],
                event["details"]["read_length"],
                event["details"]["write_count"],
                event["details"]["write_length"],
            ))
        elif name == "Frequencies of all events for a block":
            burn_height = event["details"]["burn_header_height"],
            data = BlockTxData(
                event["details"]["stacks_block_id"],
                event["details"]["burn_header_height"],
                None, # TODO - stacks_height - switch when new logs are there
                event["details"]["block_cost_limit"], # TODO - parse exec costs
                event["details"]["event_frequency_map"],
                event["details"]["contract_call_frequency_map"],
                event["details"]["anchored_block_cost"], # TODO - parse exec costs
                event["details"]["microblocks_cost"], # TODO - parse exec costs
            )
            block_tx_data[burn_height] = data
        elif name == "Full microblock":
            microblock_limit_hit.append(MicroblockLimitHit(
                event["details"]["exceeded_dimensions"],
                event["details"]["parent_tip_height"],
                event["details"]["block_limit_hit"],
            ))
        elif name == "Full block":
            anchored_block_limit_hit.append(BlockLimitHit(
                event["details"]["exceeded_dimensions"],
                event["details"]["anchor_block_tip_height"],
                event["details"]["sequence_number"],
            ))

    return (block_tenure_stats, unmatched_block_tenure, costs, block_tx_data, microblock_limit_hit, anchored_block_limit_hit)

def approx_equal(f1, f2, e=0.00001):
    if abs(f1-f2) < e:
        return True
    else:
        return False

class ExecutionCost:
    def __init__(self, runtime, read_count, read_length, write_count, write_length):
        self.runtime = runtime
        self.read_count = read_count
        self.read_length = read_length
        self.write_count = write_count
        self.write_length = write_length

    def get_limit_struct(self, limit):
        limit_struct = ExecutionCost(self.runtime/ limit.runtime, self.read_count/limit.read_count,
                                     self.read_length/limit.read_length, self.write_count/limit.write_count,
                                     self.write_length/limit.write_length)
        return limit_struct

    # limit also should have type ExecutionCost
    def limit_exceeded(self, limit, full_percentage):
        max_scalar_cost = limit.runtime * limit.read_count * limit.read_length * limit.write_count * limit.write_length
        block_scalar_cost = max(1, self.runtime) * max(1, self.read_count) * max(1, self.read_length) * max(1, self.write_count) * max(1, self.write_length)
        if (block_scalar_cost/max_scalar_cost) > full_percentage:
           return True
        return False

    def all_equal(self):
        if (approx_equal(self.runtime, self.read_count) and approx_equal(self.read_count, self.read_length) and
                approx_equal(self.read_length, self.write_count) and approx_equal(self.write_count, self.write_length)):
            return True
        else:
            return False

    def max(self):
        if self.all_equal(): return None
        cost_dim_map = {"runtime": self.runtime, "read_count": self.read_count, "read_length": self.read_length,
                        "write_count": self.write_count, "write_length": self.write_length}
        max_dim = max(cost_dim_map, key=cost_dim_map.get)
        return max_dim
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
        print(block_prod_time, block_data.is_good_commitment)
        if block_data.height not in fastest_block_tracker or block_prod_time < fastest_block_tracker[block_data.height]:
            fastest_block_tracker[block_data.height] = block_prod_time

        if block_data.is_good_commitment == True and (block_data.height not in good_block_tracker or block_prod_time < good_block_tracker[block_data.height]):
            good_block_tracker[block_data.height] = block_prod_time
            print("good block: ", block_data.height)


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

## Test for Q1/ Q2
## test case:
#     dummy_block_data = [BlockProduction(2, 5, 2, false), BlockProduction(2, 3, 2, false), BlockProduction(2, 6, 2, true)]
#     compute_q1(dummy_block_data, dummy_can_chain)
## expected ans:
#     Answering Q1: What is the average time a synchronized miner takes to broadcast a block commitment?
#     Average:  1.0
#     Answering Q2: What is the average time a synchronized miner takes to broadcast their first good block commitment?
#     Average:  4.0

## test case:
#     dummy_block_data = [BlockProduction(2, 5, 2, False), BlockProduction(2, 3, 2, False), BlockProduction(2, 6, 2, True),
#                         BlockProduction(10, 12, 3, False), BlockProduction(10, 13, 3, True), BlockProduction(10, 12, 3, True)]
#     compute_q1(dummy_block_data)
## expected ans:
#     Answering Q1: What is the average time a synchronized miner takes to broadcast a block commitment?
#     Average:  1.5
#     Answering Q2: What is the average time a synchronized miner takes to broadcast their first good block commitment?
#     Average:  3.0

# Q3
# tx_cost_data - list of ExecutionCost structs
# each map's keys are the 5 cost dimensions, the value is the percent of the block budget consumed.
def compute_q3(tx_cost_data):
    max_dim_map = defaultdict(int)
    max_dim_counter = 0
    num_txs = len(tx_cost_data)
    for cost_percent_struct in tx_cost_data:
        max_dim = cost_percent_struct.max()
        if max_dim != None:
            # print(cost_percent_struct.runtime, cost_percent_struct.read_count, cost_percent_struct.read_length, cost_percent_struct.write_count, cost_percent_struct.write_length)
            max_dim_map[max_dim] += 1
            max_dim_counter += 1

    print("Answering Q3: Determine distribution of transactions limited by each cost dimension.")
    total = sum(max_dim_map.values())
    for k in max_dim_map:
        max_dim_map[k] = max_dim_map[k]*100/total
        print(k,  max_dim_map[k])
    print(max_dim_counter, "out of", num_txs, "transactions had uneven costs.", max_dim_counter/num_txs * 100, "%.")
    return max_dim_map

## test case:
## runtime, read_count, read_length, write_count, write_length
# dummy_data = [ExecutionCost(32, 34, 10, 10, 13),
#               ExecutionCost(32, 43, 10, 10, 25),
#               ExecutionCost(32, 16, 10, 55, 17),
#               ExecutionCost(32, 12, 33, 10, 22),
#               ExecutionCost(32, 19, 39, 9, 27)]
# compute_q3(dummy_data)
# expected answer
# Answering Q3: Determine distribution of transactions limited by each cost dimension.
# read_count 40.0
# write_count 20.0
# read_length 40.0


class BlockTxData:
    def __init__(self, stacks_block_id, burn_block_height, stacks_height, block_cost_limit, event_frequency_map, contract_call_frequency_map, anchored_block_cost, microblocks_cost):
        self.stacks_block_id = stacks_block_id
        self.burn_block_height = burn_block_height
        self.stacks_height = stacks_height
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

# log data: Profiler Q4: frequencies of all events for a block,
# stacks_block_id: d2b495b167ca2c1917bc100fe25e4af93ff29f4bcdbd85f50e7d587cd79eca5f,
# event_frequency_map: "stx_lock_event": 2; "stx_transfer_event": 4; "contract_event": 2; ,
# contract_call_frequency_map: QualifiedContractIdentifier { issuer: StandardPrincipalData(SP3FBR2AGK5H9QBDH3EEN6DF8EK8JY7RX8QJ5SVTE), name: ContractName("send-many-memo") }: 2; ,
# block_cost_limit: {"runtime": 5000000000, "write_len": 15000000, "write_cnt": 7750, "read_len": 100000000, "read_cnt": 7750},
# anchored_block_cost: {"runtime": 0, "write_len": 0, "write_cnt": 0, "read_len": 0, "read_cnt": 0},
# microblocks_cost: {"runtime": 191309000, "write_len": 1698, "write_cnt": 12, "read_len": 67066, "read_cnt": 49}

# block_tx_data - map of burn block height to BlockTxData
# analyze full blocks
def compute_q4(block_tx_data, verbose=False, min_burn_height=None, full_percentage=0.9):
    total_block_count = 0
    full_block_counter = 0
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
        (limit_exceeded) = anchored_block_cost.limit_exceeded(block_cost_limit, full_percentage)

        if limit_exceeded:
            # full-ish block stats
            # - average number of contracts called in a full block
            # - total count of contracts called from full blocks
            # - percentages of which limit was hit in the block limit
            full_block_counter += 1

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
    print(full_block_counter, " out of ", total_block_count, " blocks were at least ", full_percentage*100, "percent full. ", full_block_counter/total_block_count, "%.")
    avg_contracts_called =  np.average(np.asarray(full_block_num_contracts))
    print("Average contracts called:", avg_contracts_called)
    print("Total contract call counter:", full_block_contract_counter)
    # percent_breakdown_limit = {}
    # for cost_dim, num_hits in full_block_limit_hit.iteritems():
    #     percent_breakdown_limit[cost_dim] = num_hits/full_block_counter
    # print("Percent breakdown of which cost limit was hit in a full block:", percent_breakdown_limit)


    print("Answering Q4-b: stats on all blocks")
    avg_events_per_block =  np.average(np.asarray(all_block_event_counter))
    print("Average number of events per block:", avg_events_per_block)
    print("Total event counter:", all_block_num_events)


class BlockLimitHit:
    def __init__(self, exceeded_dimensions, parent_tip_height, block_limit_hit):
        self.exceeded_dimensions = exceeded_dimensions
        self.parent_tip_height = parent_tip_height
        self.block_limit_hit = block_limit_hit
# Stats from miner regarding when the block limit is hit for anchored blocks.
# block_limit_hit_data - a list of maps of the following form:
# { "exceeded_dimensions": _,
#  "parent_tip_height": _,
#  "block_limit_hit": _ }
def compute_q5a(block_limit_hit_data):
    exceeded_dimension_counter = defaultdict(int)
    total_limits_hit = 0
    for lim_hit in block_limit_hit_data:
        exceeded_dimensions = lim_hit["exceeded_dimensions"].split(" ")
        for dim in exceeded_dimensions:
            exceeded_dimension_counter[dim] += 1
            total_limits_hit += 1
    percent_per_dim = {}
    for cost_dim, num_hits in exceeded_dimension_counter:
        percent_per_dim[cost_dim] = num_hits/total_limits_hit

class MicroblockLimitHit:
    def __init__(self, exceeded_dimensions, anchor_block_tip_height, sequence_number):
        self.exceeded_dimensions = exceeded_dimensions
        self.anchor_block_tip_height = anchor_block_tip_height
        self.sequence_number = sequence_number

# Stats from miner regarding when the block limit is hit for microblocks.
# microblock_limit_hit_data - a list of maps of the following form:
# { "exceeded_dimensions": _,
# "anchor_block_tip_height": _,
# "sequence_number": _ }
def compute_q5b(microblock_limit_hit_data):
    exceeded_dimension_counter = defaultdict(int)
    total_limits_hit = 0
    for lim_hit in microblock_limit_hit_data:
        exceeded_dimensions = lim_hit["exceeded_dimensions"].split(" ")
        for dim in exceeded_dimensions:
            exceeded_dimension_counter[dim] += 1
            total_limits_hit += 1
    percent_per_dim = {}
    for cost_dim, num_hits in exceeded_dimension_counter:
        percent_per_dim[cost_dim] = num_hits/total_limits_hit


def parse_log_file(file_name="sample_logs.txt"):
    events = parse_logs(file_name)
    block_tenure_stats, unmatched_block_tenure, costs, block_tx_data, microblock_limit_hit, anchored_block_limit_hit = process_events(events)

    # print(block_tenure_stats)
    # print(costs)
    # print(block_tx_data)

    print("Number of unmatched block tenure stats: ", len(unmatched_block_tenure))
    print("Number of matched block tenure stats", len(block_tenure_stats))

    compute_q1(block_tenure_stats)


##### Call computation functions

## JSON data for transactions
def parse_json_file():
    block_limit = ExecutionCost(5000000000, 7750, 100000000, 7750, 15000000)
    f = open('execution-events.json')
    data = json.load(f)

    count = 0
    percent_data = []
    event_freq_map = defaultdict(int)
    for event in data:
        event_name = event["name"]
        event_freq_map[event_name] += 1
        event_cost = ExecutionCost(event["runtime"], event["read-count"], event["read-length"], event["write-count"], event["write-length"])
        percent_struct = event_cost.get_limit_struct(block_limit)
        percent_data.append(percent_struct)
        count += 1

    print("Event frequencies for event data: ", event_freq_map)
    compute_q3(percent_data)

    # Closing file
    f.close()
