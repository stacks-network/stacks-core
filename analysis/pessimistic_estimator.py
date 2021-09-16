import sys
import collections
import matplotlib.pyplot

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

def extract_array(kv_array, key, converter):
	result = []
	for kv in kv_array:
		result.append(converter(kv[key]))
	return result

	
contract_counter = collections.Counter()

kv_list = []
for line in sys.stdin:
	kv = {}
	if "PessimisticEstimator received event" in line:
		print(line)
		additions = rust_to_map(line)
		kv.update(additions)

	if "data:header_info" in line:
		extract_structured_field_into(line, 'block_height', kv)
		extract_structured_field_into(line, 'consensus_hash', kv)

	if "New data event received" in line:
		kv['elements'].append(rust_to_map(line))

		kv_list.append(kv)

	contract_counter.update([kv['key']])



print ('contract_counter', contract_counter)

actual_array = extract_array(kv_list, 'actual', float)
estimate_array = extract_array(kv_list, 'estimate', float)
estimate_err_array = extract_array(kv_list, 'estimate_err', float)
estimate_err_pct_array = extract_array(kv_list, 'estimate_err_pct', float)

x_coords = range(0, len(estimate_err_pct_array))

ones =  [1.0 for x in x_coords]

matplotlib.pyplot.bar(x_coords, sorted(estimate_err_pct_array))
matplotlib.pyplot.plot(x_coords, ones, color='red')


under = 0
over = 0
same = 0
total = 0
for x in estimate_err_pct_array:
	total += 1
	if x < 1:
		under += 1
	elif x > 1:
		over += 1
	else:
		same += 1


print('under', under)
print('over', over)
print('same', same)
print('total', total)

matplotlib.pyplot.show()
