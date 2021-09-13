from collections import Counter, defaultdict



### Analysis
# Q1, Q2
class BlockProduction:
    def __init__(self, start_time, end_time, height, ancestor_block_header_hash):
        self.start_time = start_time
        self.end_time = end_time
        self.height = height
        self.ancestor_block_header_hash = ancestor_block_header_hash

# data - list of BlockProduction stats
#   --> a data point should be produced every time a block commitment is produced (so when the log line is created at
#       the end of RunTenure
#   --> there can be multiple end_times for the same start_time
#   --> some start_times may not be associated with any end_time (for example, for the blocks downloaded during ibd)
# canonical_chain - map of height to BHH of canonical chain
# QUESTION: how to get the canonical block chain?
def compute_q1(data, canonical_chain):
    fastest_block_tracker = {}
    good_block_tracker = {}

    for block_data in data:
        block_prod_time = block_data.end_time - block_data.start_time
        if block_data.height not in fastest_block_tracker or block_prod_time < fastest_block_tracker[block_data.height]:
            fastest_block_tracker[block_data.height] = block_prod_time

        has_good_ancestor = canonical_chain[block_data.height - 1] == block_data.ancestor_block_header_hash
        if has_good_ancestor and (block_data.height not in good_block_tracker or block_prod_time < good_block_tracker[block_data.height]):
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
#     dummy_can_chain = {1: "abcd", 2: "efgh", 3: "ijkl", 4: "mnop", 5: "qrst"}
#     dummy_block_data = [BlockProduction(2, 5, 2, "agff"), BlockProduction(2, 3, 2, "agff"), BlockProduction(2, 6, 2, "abcd")]
#     compute_q1(dummy_block_data, dummy_can_chain)
# expected ans:
#     Answering Q1: What is the average time a synchronized miner takes to broadcast a block commitment?
#     Average:  1.0
#     Answering Q2: What is the average time a synchronized miner takes to broadcast their first good block commitment?
#     Average:  4.0

# test case:
#     dummy_can_chain = {1: "abcd", 2: "efgh", 3: "ijkl", 4: "mnop", 5: "qrst"}
#     dummy_block_data = [BlockProduction(2, 5, 2, "agff"), BlockProduction(2, 3, 2, "agff"), BlockProduction(2, 6, 2, "abcd"),
#                         BlockProduction(10, 12, 3, "weal"), BlockProduction(10, 13, 3, "efgh"), BlockProduction(10, 12, 3, "efgh")]
#     compute_q1(dummy_block_data, dummy_can_chain)
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

    print("Answering Q3: Determine distribution of tx's limited by each cost dimension.")
    total = sum(counter.values())
    for k in counter:
        counter[k] = counter[k]*100/total
        print(k,  counter[k])
    return counter

dummy_data = [{"read_count": 34, "read_length": 10, "write_count": 10, "write_length": 13, "runtime": 32},
              {"read_count": 43, "read_length": 10, "write_count": 10, "write_length": 25, "runtime": 32},
              {"read_count": 16, "read_length": 10, "write_count": 55, "write_length": 17, "runtime": 32},
              {"read_count": 12, "read_length": 33, "write_count": 10, "write_length": 22, "runtime": 32},
              {"read_count": 19, "read_length": 39, "write_count": 9, "write_length": 27, "runtime": 32}]

compute_q3(dummy_data)