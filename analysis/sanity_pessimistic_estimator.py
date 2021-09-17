import sys
import collections
import json
import numpy

import pessimistic_estimator
import error_functions

data_fname = sys.argv[1]

model = pessimistic_estimator.PessimisticModel()

with open(data_fname, 'r') as data_file:
    lines = data_file.readlines()

key_to_last_estimate = {}
key_to_num_estimates = collections.defaultdict(int)
for idx, line in enumerate(lines):
    data_point = json.loads(line)
    data_key = data_point['key']

    # Make the estimate first.
    python_estimate = model.create_estimate(data_key)

    # Update the samples.
    elements = data_point['elements']
    model.update(elements)
    
    # Store the estimate.
    rust_estimate = data_point['estimate']
    gold_cost = data_point['actual']

    key_to_last_estimate[data_key] = (python_estimate, rust_estimate)
    key_to_num_estimates[data_key] += 1

for key, pair in key_to_last_estimate.iteritems():
    num_estimates = key_to_num_estimates[key]
    parts = [key, pair[0], pair[1], num_estimates]
    csv = ','.join([str(p) for p in parts])
    print csv
