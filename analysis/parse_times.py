import sys

fname = sys.argv[1]
print('fname', fname)

lines = open(fname, 'r').readlines()

total = 0
c_vector = []
matching = 0
for line in lines:
    if 'MarfConnection::get' not in line:
        continue
    matching += 1

    time_part = line.split('time_cost=')[1].split(')')[0]

    factor = 1.0
    if time_part.endswith('ms'):
        factor = 0.001
    elif time_part.endswith('µs'):
        factor = 0.001 * 0.001
    else:
        print('time_part', time_part)

    number_part = time_part[:-2]
    f = float(number_part)

    c = f * factor
    c_vector.append(c)
    total += c

print('lines', matching)
print('total', total)

ts = sorted(c_vector)
# print('ts', ts)
