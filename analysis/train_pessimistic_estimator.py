import sys
import collections
import json
import numpy

data_fname = sys.argv[1]

active_N = 10

"""
Maintains a set of the N highest samples we have seen so far.
This is used to implemente the `PessimisticEstimator` in the rust code.
"""
class PessimisticSample(object):
    def __init__(self, N):
        # The number of samples to remember.
        self._N = N
        # The entries we are tracking, stored as a simple vector.
        self._entries = []
        # We store the mean, and use `0` as the mean of no samples to get started.
        self._mean = 0.0

    """
    If `point` is greater than the smallest point in `self._entries`, replace entry
    with `point`.
    """
    def insert(self, point):
        # print('before', self._entries, point)
        if len(self._entries) < self._N:
            self._entries.append(point)
        else:
            min_val = self._entries[0]
            min_idx = 0
            for idx, val in enumerate(self._entries):
                if val < min_val:
                    min_val = val
                    min_idx = idx
            if point > min_val:
                self._entries[min_idx] = point
        self._mean = numpy.mean(self._entries)
        # print('after', self._entries, self._mean)

    def mean(self):
        return self._mean

BLOCK_LIMIT_MAINNET = [
    5000000000, # runtime: 
    15000000, # write_length: 
    7750, # write_count: 
    100000000, # read_length: 
    7750, # read_count: 
    ]
def create_point_estimate(estimate_components):
    sigma = 0.0
    for idx, number in enumerate(estimate_components):
        part = number * 1.0 / BLOCK_LIMIT_MAINNET[idx] * 1000
        sigma += part
    return sigma

"""
Creates an estimate of the cost based on the five hard-coded dimensions.
"""
def create_estimate(key_to_samples, event_key):
    event_base = event_key.split(':runtime')[0]
    component_name = [':runtime', ':write-length', ':write-count', ':read-length', ':read-count']
    estimate_components = []
    for component_name in component_name:
        full_key = event_base + component_name
        samples = key_to_samples[full_key]
        estimate_components.append(samples.mean())
    estimate = create_point_estimate(estimate_components)
    # print ('estimate', estimate)
    return estimate

data_rows = []
with open(data_fname, 'r') as data_file:
    lines = data_file.readlines()

def new_estimator():
    return PessimisticSample(active_N)

key_to_samples = collections.defaultdict(new_estimator)
key_to_last_estimate = {}
key_to_num_estimates = collections.defaultdict(int)

for idx, line in enumerate(lines):
    data_point = json.loads(line)
    data_key = data_point['key']

    # Make the estimate first.
    offline_estimate = create_estimate(key_to_samples, data_key)

    # Update the samples.
    elements = data_point['elements']
    for element in elements:
        key = element['key']
        value = int(element['value'])
        key_to_samples[key].insert(value)
    
    # Store the estimate.
    given_estimate = data_point['estimate']
    key_to_last_estimate[data_key] = (offline_estimate, given_estimate)
    key_to_num_estimates[data_key] += 1


for key, pair in key_to_last_estimate.iteritems():
    num_estimates = key_to_num_estimates[key]
    parts = [key, pair[0], pair[1], num_estimates]
    csv = ','.join([str(p) for p in parts])
    print csv
