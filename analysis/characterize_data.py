import sys
import collections
import json
import numpy

data_fname = sys.argv[1]

with open(data_fname, 'r') as data_file:
    lines = data_file.readlines()

data_rows = []
for idx, line in enumerate(lines):
    data_rows.append(json.loads(line))

print('number of data rows:', len(data_rows))
print('highest block height:', data_rows[-1]['block_height'])
