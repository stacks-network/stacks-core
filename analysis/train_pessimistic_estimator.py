import sys
import collections
import json
import numpy

data_fname = sys.argv[1]
print(data_fname)

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
    def mean(self):
        return self._mean

data_rows = []
with open(data_fname, 'r') as data_file:
    lines = data_file.readlines()
print (len(lines))

def new_estimator():
    return PessimisticSample(active_N)
element_samples = collections.defaultdict(new_estimator)

for idx, line in enumerate(lines):
    data_point = json.loads(line)
    elements = data_point['elements']
    for element in elements:
        key = element['key']
        value = int(element['value'])
        element_samples['key'].insert(value)
    

