import sys
import collections
import matplotlib.pyplot
import collections

"""
Converts a Rust-style structured output line to a python-style dict.

Input format is like:
	INFO [1631296771.981741] [src/cost_estimates/pessimistic.rs:213] [chains-coordinator] PessimisticEstimator received event, key: coinbase:runtime, estimate: 0, actual: 1, estimate_err: -1, estimate_err_pct: -1

Output is a dict mapping strings to strings.
"""
def rust_to_map(line):
	parts = line.rstrip().split(', ')
	result = {}
	for part in parts[1:]:
		inner_parts = part.split(': ', 2)
		result [inner_parts[0]] = inner_parts[1]
	return result

"""
Hacky function, that takes a key like `version`, and picks out the atomic value
associated with that.

Takes a line like:
WARN [1631725964.876143] [src/chainstate/coordinator/mod.rs:681] [chains-coordinator] data:header_info StacksHeaderInfo { anchored_header: StacksBlockHeader { version: 0, total_work: StacksWorkScore { burn: 3788391672, work: 2186 } } }
"""
def extract_structured_field_into(line, key, kv):
	outer_split = key + ': '
	outer_parts = line.split(outer_split)
	assert(len(outer_parts) > 1)
	inner_split = outer_parts[1].split(',')
	value = inner_split[0]
	kv[key] = value

kv_list = []

header_kv = []
kv = []
for line in sys.stdin:
	if "data:header_info" in line:
		print ('kv', kv)
		header_kv = collections.defaultdict(list)
		extract_structured_field_into(line, 'block_height', header_kv)
		extract_structured_field_into(line, 'consensus_hash', header_kv)

	if "PessimisticEstimator received event" in line:
		# print(line)
		kv = collections.defaultdict(list)
		kv.update(header_kv)
		additions = rust_to_map(line)
		kv.update(additions)

	if "New data event received" in line:
		# print(line)
		kv['elements'].append(rust_to_map(line))
		kv_list.append(kv)



