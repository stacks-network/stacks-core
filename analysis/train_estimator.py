import sys
import collections
import json
import numpy

import pessimistic_estimator
import average_estimator
import error_functions

data_fname = sys.argv[1]
model_name = sys.argv[2]

model_dict = {
        'pessimistic' : pessimistic_estimator.Model(),
        'average' : average_estimator.Model(),
}

model = model_dict[model_name]

with open(data_fname, 'r') as data_file:
    lines = data_file.readlines()

gold_costs = []
pred_costs = []
for idx, line in enumerate(lines):
    data_point = json.loads(line)
    data_key = data_point['key']

    # Make the estimate first.
    offline_estimate = model.create_estimate(data_key)

    # Update the samples.
    elements = data_point['elements']
    model.update(elements)
    
    # Store the estimate.
    rust_estimate = data_point['estimate']
    gold_cost = data_point['actual']

    pred_costs.append(offline_estimate)
    gold_costs.append(float(gold_cost))

for error_function in error_functions.all_functions:
    error = error_function(gold_costs, pred_costs)
    parts = [
        model_name,
        error_function.__name__,
        str(error),
        ]
    print(','.join(parts))
