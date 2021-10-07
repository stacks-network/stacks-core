from collections import Counter, defaultdict
import csv
import json
import numpy as np
import sys

## Question Docs
# Q1: How long does it take How long does it take an already-synchronized miner
#     to broadcast their first good commitment to a new block (i.e., one that builds on the previous winner)?
# Q2: How long does it take an already-synchronized miner to broadcast their first good commitment to a new
#     block (i.e., one that builds on the previous winner)?
# Q3: What distribution of transactions are limited by runtime, read count, write count, etc.?
# Q4: What are the relative frequencies of different event types? (this breaks down by contract)
# Q5: (a) If an anchored block's cost limit is hit during mining, this logs which dimension it was.
#     (b) Same analysis done for microblocks.
# Q6: How long does it take a follower to process an epoch? (logs time in `append_block`)
# Q7: No logging - how long does it take to start a non-sidecar follower from genesis?
# Q8: How long does it take a miner to assemble a block?

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
    return ExecutionCost(
        input["runtime"],
        input["read_count"],
        input["read_length"],
        input["write_count"],
        input["write_length"],
    )


def process_events(events):
    tx_costs = {}
    block_limit = None
    block_tenure_stats = []
    unmatched_block_tenure = []
    anchored_block_limit_hit = []
    microblock_limit_hit = []
    insert_events = {}
    block_tx_data = {}
    block_processing_times = []
    node_start_time = None
    node_startup_time = None
    mining_times = []
    for event in events:
        name = event["event"]
        # Q1 & Q2
        if name == "Inserting new bitcoin header":
            height = event["details"]["new_burn_height"]
            if height not in insert_events:
                insert_events[height] = event
        elif name == "Finished running tenure":
            last_burn_height = event["details"]["last_burn_height"]
            if last_burn_height not in insert_events:
                unmatched_block_tenure.append(last_burn_height)
            last_insert_at_height = insert_events[last_burn_height]
            is_good_commitment = None
            if event["details"]["is_good_commitment_opt"] != "none":
                is_good_commitment = event["details"]["is_good_commitment_opt"] == "true"
            if last_insert_at_height:
                block_tenure_stats.append(BlockProduction(
                    last_insert_at_height["details"]["timestamp"],
                    event["details"]["timestamp"],
                    last_burn_height,
                    is_good_commitment
                ))
        # Q3
        elif name == "Execution cost of processed transaction":
            tx_id = event["details"]["txid"]
            if block_limit == None:
                block_limit = parse_execution_cost(event["details"]["block_cost_limit"])
            tx_cost = parse_execution_cost(event["details"])
            tx_costs[tx_id] = tx_cost
        # Q4
        elif name == "Frequencies of all events for a block":
            burn_height = event["details"]["burn_header_height"]
            data = BlockTxData(
                event["details"]["stacks_block_id"],
                event["details"]["burn_header_height"],
                event["details"]["stacks_block_height"],
                parse_execution_cost(event["details"]["block_cost_limit"]),
                event["details"]["event_frequency_map"],
                parse_execution_cost(event["details"]["anchored_block_cost"]),
                parse_execution_cost(event["details"]["microblocks_cost"]),
            )
            block_tx_data[burn_height] = data
        # Q5a
        elif name == "Full block":
            anchored_block_limit_hit.append(BlockLimitHit(
                event["details"]["exceeded_dimensions"],
                event["details"]["parent_tip_height"],
                event["details"]["block_limit_hit"],
            ))
        # Q5b
        elif name == "Full microblock":
            microblock_limit_hit.append(MicroblockLimitHit(
                event["details"]["exceeded_dimensions"],
                event["details"]["anchored_block_tip_height"],
                event["details"]["sequence_number"],
            ))
        # Q6
        elif name == "End of processing block":
            elapsed = event["details"]["timestamp"] - event["details"]["start_timestamp"]
            block_processing_times.append((event["details"]["timestamp"], event["details"]["start_timestamp"], elapsed))
        # Q7
        elif name == "Node starting up":
            node_start_time = event["details"]["timestamp"]
        elif name == "Node fully caught up":
            if node_startup_time == None and node_start_time != None:
                node_startup_time = (node_start_time, event["details"]["timestamp"], event["details"]["timestamp"] - node_start_time)
        # Q8
        elif name == "Miner assembled block":
            mining_times.append((event["details"]["block_header_hash"], event["details"]["mining_time"]))

    return (block_tenure_stats, unmatched_block_tenure, tx_costs, block_limit, block_tx_data, microblock_limit_hit,
            anchored_block_limit_hit, block_processing_times, node_startup_time, mining_times)

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

    def __repr__(self):
        result = "\n{ runtime: %s" % self.runtime
        result += "\nread_count: %s" % self.read_count
        result += "\nread_length: %s" % self.read_length
        result += "\nwrite_count: %s" % self.write_count
        result += "\nwrite_length: %s }" % self.write_length

        return result

    def get_percent_struct(self, limit):
        percent_struct = ExecutionCost(self.runtime/ limit.runtime, self.read_count/limit.read_count,
                                     self.read_length/limit.read_length, self.write_count/limit.write_count,
                                     self.write_length/limit.write_length)
        return percent_struct

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

def compute_stats_for_block_commitment(commitment_map):
    num_values = len(commitment_map)
    if num_values == 0:
        print("No values...")
        return
    elapsed_times = [elapsed for  (_, _, elapsed) in list(commitment_map.values())]
    # values = np.array(list(commitment_map.values()))
    values = np.array(elapsed_times)
    f_perc = np.percentile(values, 5)
    avg = np.percentile(values, 50)
    nf_perc = np.percentile(values, 95)

    print("5th percentile:", f_perc)
    print("50th percentile:", avg)
    print("95th percentile:", nf_perc)
    print("Num values:", num_values)


# data - list of BlockProduction stats
#   --> a data point should be produced every time a block commitment is produced (so when the log line is created at
#       the end of RunTenure
#   --> there can be multiple end_times for the same start_time
#   --> some start_times may not be associated with any end_time (for example, for the blocks downloaded during ibd)
# canonical_chain - map of height to BHH of canonical chain
# QUESTION: how to get the canonical block chain?
def compute_q1_and_q2(data, raw_data_dir):
    fastest_block_tracker = {}
    good_block_tracker = {}

    for block_data in data:
        block_prod_time = block_data.end_time - block_data.start_time
        if block_data.height not in fastest_block_tracker or block_prod_time < fastest_block_tracker[block_data.height][2]:
            fastest_block_tracker[block_data.height] = (block_data.start_time, block_data.end_time, block_prod_time)

        if block_data.is_good_commitment == True and (block_data.height not in good_block_tracker or block_prod_time < good_block_tracker[block_data.height][2]):
            good_block_tracker[block_data.height] = (block_data.start_time, block_data.end_time, block_prod_time)

    # Q1
    print("\nAnswering Q1: What is the average time (in ms) a synchronized miner takes to broadcast a block commitment?")
    compute_stats_for_block_commitment(fastest_block_tracker)

    # Q2
    print("\nAnswering Q2: What is the average time (in ms) a synchronized miner takes to broadcast their first good block commitment?")
    compute_stats_for_block_commitment(good_block_tracker)

    file_path = raw_data_dir + "/" +"q1.csv"
    headers = ["start_time (ms)", "end_time (ms)", "elapsed_time (ms)"]
    with open(file_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for data in fastest_block_tracker.values():
            row = [data[0], data[1], data[2]]
            writer.writerow(row)

    file_path = raw_data_dir + "/" +"q2.csv"
    with open(file_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for data in good_block_tracker.values():
            row = [data[0], data[1], data[2]]
            writer.writerow(row)

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

# Q3:  What distribution of transactions are limited by runtime, read count, write count, etc.?
# tx_cost_data - a list of ExecutionCost structs (each represents the cost of one transaction
# block_limit - an ExecutionCost struct representing the block limit
def compute_q3(tx_cost_data, block_limit, raw_data_dir):
    log_data = []
    max_dim_map = defaultdict(int)
    max_dim_counter = 0
    num_txs = len(tx_cost_data)
    for _txid, cost_struct in tx_cost_data.items():
        curr_row_data = [cost_struct.runtime, cost_struct.read_count, cost_struct.read_length, cost_struct.write_count, cost_struct.write_length]
        cost_percent_struct = cost_struct.get_percent_struct(block_limit)
        curr_row_data.extend([cost_percent_struct.runtime, cost_percent_struct.read_count, cost_percent_struct.read_length, cost_percent_struct.write_count, cost_percent_struct.write_length])
        max_dim = cost_percent_struct.max()
        curr_row_data.append(max_dim)
        if max_dim != None:
            max_dim_map[max_dim] += 1
            max_dim_counter += 1

        log_data.append(curr_row_data)

    print("\nAnswering Q3: Determine distribution of transactions limited by each cost dimension.")
    total = sum(max_dim_map.values())
    for k in max_dim_map:
        max_dim_map[k] = max_dim_map[k]*100/total
        print(k,  max_dim_map[k])
    print(max_dim_counter, "out of", num_txs, "transactions had singularly large cost dimension.", max_dim_counter/num_txs * 100, "%.")

    file_path = raw_data_dir + "/" +"q3.csv"
    headers = ["runtime", "read_count", "read_length", "write_count", "write_length", "runtime (%)", "read_count (%)", "read_length (%)", "write_count (%)", "write_length (%)", "max_dimension"]
    with open(file_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(headers)

        writer.writerows(log_data)

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
    def __init__(self, stacks_block_id, burn_block_height, stacks_height, block_cost_limit, event_frequency_map, anchored_block_cost, microblocks_cost):
        self.stacks_block_id = stacks_block_id
        self.burn_block_height = burn_block_height
        self.stacks_height = stacks_height
        self.block_cost_limit = block_cost_limit # type ExecutionCost
        self.event_frequency_map = event_frequency_map # map of event name to count
        self.anchored_block_cost = anchored_block_cost
        self.microblocks_cost = microblocks_cost


# Q4: What are the relative frequencies of different event types? (this breaks down by contract)
# block_tx_data - map of burn block height to BlockTxData
# min_burn_height - only compute stats for blocks with a height greater than or equal to this value
def compute_q4(block_tx_data, raw_data_dir, min_burn_height=None):
    all_block_num_events = []
    all_block_event_counter = defaultdict(int)
    log_dict = {}
    for burn_height, curr_block_data in block_tx_data.items():
        # If min_burn_height is set, don't consider blocks with lesser heights
        if min_burn_height != None and burn_height < min_burn_height:
            continue

        # - avg number of total events
        # - total count of each event across all blocks
        total_event_count = 0
        for event_id, event_count in curr_block_data.event_frequency_map.items():
            total_event_count += event_count
            all_block_event_counter[event_id] += event_count
        all_block_num_events.append(total_event_count)
        log_dict[burn_height] = curr_block_data.event_frequency_map

    print("\nAnswering Q4: stats on all blocks")
    avg_events_per_block =  np.average(np.asarray(all_block_num_events))
    print("Average number of events per block: ", avg_events_per_block)
    print("Total event map: ", all_block_event_counter)

    file_path = raw_data_dir + "/" +"q4.json"
    with open(file_path, 'w') as f:
        json.dump(log_dict, f)


class BlockLimitHit:
    def __init__(self, exceeded_dimensions, parent_tip_height, block_limit_hit):
        self.exceeded_dimensions = exceeded_dimensions
        self.parent_tip_height = parent_tip_height
        self.block_limit_hit = block_limit_hit

# Q5a: If an anchored block's cost limit is hit, this logs which dimension it was.
# Stats from miner regarding when the block limit is hit for anchored blocks.
# block_limit_hit_data - a list of maps of the following form:
# { "exceeded_dimensions": _,
#  "parent_tip_height": _,
#  "block_limit_hit": _ }
def compute_q5a(block_limit_hit_data, total_blocks_mined, raw_data_dir):
    exceeded_dimension_counter = defaultdict(int)
    total_limits_hit = 0
    for lim_hit in block_limit_hit_data:
        exceeded_dimensions = lim_hit.exceeded_dimensions.split(";")
        for dim in exceeded_dimensions:
            exceeded_dimension_counter[dim] += 1
            total_limits_hit += 1
    percent_per_dim = {}
    for cost_dim, num_hits in exceeded_dimension_counter.items():
        percent_per_dim[cost_dim] = num_hits/total_limits_hit * 100

    print("\nAnswering Q5a: stats on full blocks")
    print("Num of full blocks:", len(block_limit_hit_data))
    print("Num of total blocks:", total_blocks_mined)
    print("Percent breakdown of which limit is hit:", percent_per_dim)

    file_path = raw_data_dir + "/" +"q5.json"
    with open(file_path, 'w') as f:
        json.dump(block_limit_hit_data, f)

class MicroblockLimitHit:
    def __init__(self, exceeded_dimensions, anchor_block_tip_height, sequence_number):
        self.exceeded_dimensions = exceeded_dimensions
        self.anchor_block_tip_height = anchor_block_tip_height
        self.sequence_number = sequence_number

# Q5a: If a microblock's cost limit is hit, this logs which dimension it was.
# Stats from miner regarding when the block limit is hit for microblocks.
# microblock_limit_hit_data - a list of maps of the following form:
# { "exceeded_dimensions": _,
# "anchor_block_tip_height": _,
# "sequence_number": _ }
def compute_q5b(microblock_limit_hit_data, raw_data_dir):
    exceeded_dimension_counter = defaultdict(int)
    total_limits_hit = 0
    for lim_hit in microblock_limit_hit_data:
        exceeded_dimensions = lim_hit["exceeded_dimensions"].split(" ")
        for dim in exceeded_dimensions:
            exceeded_dimension_counter[dim] += 1
            total_limits_hit += 1
    percent_per_dim = {}
    for cost_dim, num_hits in exceeded_dimension_counter.items():
        percent_per_dim[cost_dim] = num_hits/total_limits_hit * 100

    print("\nAnswering Q5b: stats on full microblocks")
    print("Num of full microblocks:", len(microblock_limit_hit_data))
    print("Percent breakdown of which limit is hit:", percent_per_dim)

    file_path = raw_data_dir + "/" +"q5b.json"
    with open(file_path, 'w') as f:
        json.dump(microblock_limit_hit_data, f)

# Q6: How long does it take a follower to process an epoch? (logs time in `append_block`)
def compute_q6(processing_times, raw_data_dir):
    elapsed_times = [elapsed for (_, _, elapsed) in processing_times]
    data = np.array(elapsed_times)
    f_perc = np.percentile(data, 5)
    avg = np.percentile(data, 50)
    nf_perc = np.percentile(data, 95)

    print("\nAnswering Q6: Amount of time (in ms) it takes to process a block")
    print("5th percentile:", f_perc)
    print("50th percentile:", avg)
    print("95th percentile:", nf_perc)
    print("Num values:", len(elapsed_times))

    file_path = raw_data_dir + "/" +"q6.csv"
    headers = ["start_time (ms)", "end_time (ms)", "elapsed_time (ms)"]
    with open(file_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(processing_times)


# Q7: No logging - how long does it take to start a non-sidecar follower from genesis?
def compute_q7(node_startup_data, raw_data_dir):
    print("\nAnswering Q7: amount of time (in secs) to start a node from genesis")
    print("Elapsed time (secs): ", node_startup_data[2])

    file_path = raw_data_dir + "/" +"q7.csv"
    headers = ["start_time (ms)", "end_time (ms)", "elapsed_time (ms)"]
    with open(file_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerow(node_startup_data)

# Q8: How long does it take a miner to assemble a block?
def compute_q8(mining_data, raw_data_dir):
    mining_times = [mining_time for (_, mining_time) in mining_data]
    data = np.array(mining_times)
    f_perc = np.percentile(data, 5)
    avg = np.percentile(data, 50)
    nf_perc = np.percentile(data, 95)

    print("\nAnswering Q8: amount of time (in ms) to mine a block")
    print("5th percentile:", f_perc)
    print("50th percentile:", avg)
    print("95th percentile:", nf_perc)
    print("Num values:", len(mining_times))

    file_path = raw_data_dir + "/" +"q8.csv"
    headers = ["block_header_hash", "mining_time (ms)"]
    with open(file_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(mining_data)


def compute_stats_from_log_file(file_name="sample_logs.txt", raw_data_dir="raw_data"):
    events = parse_logs(file_name)
    (block_tenure_stats, unmatched_block_tenure, tx_costs, block_limit, block_tx_data, microblock_limit_hit,
     anchored_block_limit_hit, block_processing_times, node_startup_time, mining_times) = process_events(events)

    print("Number of created blocks with no matching burn blocks: ", len(unmatched_block_tenure))

    print("Starting computation of block stats...")

    compute_q1_and_q2(block_tenure_stats, raw_data_dir)
    compute_q3(tx_costs, block_limit, raw_data_dir)
    compute_q4(block_tx_data, raw_data_dir)
    compute_q5a(anchored_block_limit_hit, len(mining_times), raw_data_dir)
    compute_q5b(microblock_limit_hit, raw_data_dir)
    compute_q6(block_processing_times, raw_data_dir)
    compute_q7(node_startup_time)
    compute_q8(mining_times, raw_data_dir)

##### Call computation functions
## JSON data for transactions
def parse_json_file():
    block_limit = ExecutionCost(5000000000, 7750, 100000000, 7750, 15000000)
    f = open('execution-events.json')
    data = json.load(f)

    count = 0
    tx_data = []
    event_freq_map = defaultdict(int)
    for event in data:
        event_name = event["name"]
        event_freq_map[event_name] += 1
        event_cost = ExecutionCost(event["runtime"], event["read-count"], event["read-length"], event["write-count"], event["write-length"])
        tx_data.append(event_cost)
        count += 1

    print("Event frequencies for event data: ", event_freq_map)
    compute_q3(tx_data, block_limit)

    # Closing file
    f.close()


if __name__ == "__main__":
    file_name = "sample_logs.txt"
    if len(sys.argv) >= 2:
        file_name = str(sys.argv[1])
    compute_stats_from_log_file(file_name)