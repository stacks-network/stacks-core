import sys
import collections
import json

data_fname = sys.argv[1]
print(data_fname)

data_rows = []
with open(data_fname, 'r') as data_file:
    lines = data_file.readlines()
print (len(lines))


for line in lines:
    data_point = json.loads(line)
    print(data_point)
    break
    

