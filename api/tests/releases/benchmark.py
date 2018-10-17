#!/usr/bin/env python2

import os
import sys
import requests
import json
import time
import traceback
import threading
import subprocess
import tempfile

WARN = False

def parse_api_list(data):
    # data is a series of lines with API calls
    # empty lines are permitted
    # line fragments after a '#' are considered comments
    return filter(lambda l: len(l) > 0, [l2.strip().split('#')[0].strip() for l2 in data.split('\n')])
   

def run_benchmark(route, host, iters, slot, print_out):
    samples = []
    for i in range(0,iters):
        try:
            t1 = time.time()
            r = requests.get(host + route, allow_redirects=False)
            t2 = time.time()

            samples.append({
                'status': r.status_code,
                'time': t2 - t1
            })

            if r.status_code >= 500:
                print >> sys.stderr, 'HTTP {} {}'.format(r.status_code, route)

        except Exception as e:
            print >> sys.stderr, e
            samples.append({
                'time': -1,
                'error': e
            })

    if print_out:
        print json.dumps(samples)

    return samples


def benchmark_call(route, host, iters, num_threads):
    print 'check {}'.format(route)

    all_samples = [[]] * num_threads

    samples = []
    if num_threads == 1:
        samples = run_benchmark(route, host, iters, 0, False)

    else:
        threads = []
        working_dir = tempfile.mkdtemp()
        for i in range(0, num_threads):
            t = subprocess.Popen([sys.argv[0], 'benchmark', route, host, str(iters), str(i)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            threads.append(t)

        for i in range(0, num_threads):
            out, err = t.communicate()
            if t.returncode != 0:
                print >> sys.stderr, err
                samples.append([])
            else:
                samples.append(json.loads(out.strip()))
            
        samples = reduce(lambda s1, s2: s1 + s2, all_samples, [])

    # any errors?  consistent return codes?
    server_errors = 0
    exceptions = 0
    return_code = None
    for sample in samples:
        if return_code is None:
            return_code = sample.get('status')

        if sample['status'] != return_code:
            return_code = False

        if sample.get('status', 0) >= 500:
            server_errors += 1

        if sample.get('error'):
            exceptions += 1

    if return_code:
        print >> sys.stderr, '{} {}'.format(return_code, route)
    else:
        print >> sys.stderr, '(amb) {}'.format(route)

    if server_errors > 0 or exceptions > 0:
        print >> sys.stderr, '  {:.2f}% server success rate on {}'.format(100 * (1.0 - float(server_errors) / iters), route)
        print >> sys.stderr, '  {:.2f}% client success rate on {}'.format(100 * (1.0 - float(exceptions) / iters), route)

    if server_errors == iters or exceptions == iters:
        print >> sys.stderr, '  No useful timing information'
        return 

    sorted_times = filter(lambda t: t.get('time', 0) > 0, samples)
    sorted_times.sort()

    total_time = sum(s['time'] for s in sorted_times)

    avg_time = float(total_time) / (iters - max(server_errors, exceptions))
    med_time = sorted_times[len(sorted_times)/2]['time']
    _90th_time = sorted_times[(len(sorted_times) * 9) / 10]['time']
    _99th_time = sorted_times[(len(sorted_times) * 99) / 100]['time']

    print >> sys.stderr, '  Avg: {}'.format(avg_time)
    print >> sys.stderr, '  Med: {}'.format(med_time)
    print >> sys.stderr, '  90%: {}'.format(_90th_time)
    print >> sys.stderr, '  99%: {}'.format(_99th_time)

    print >> sys.stderr, ''
    return


def run_test(path, host, iters, num_threads):
    with open(path, 'r') as f:
        data = f.read()
        api_calls = parse_api_list(data)
        for api_call in api_calls:
            benchmark_call(api_call, host, iters, num_threads)
    

if __name__ == '__main__':
    if len(sys.argv) >= 2 and sys.argv[1] == 'benchmark':
        # multi-threaded worker 
        route = sys.argv[2]
        host = sys.argv[3]
        iters = int(sys.argv[4])
        slot = int(sys.argv[5])
        run_benchmark(route, host, iters, slot, True)
        sys.exit(0)

    try:
        api_tests = sys.argv[1]
        host = sys.argv[2]
        iters = int(sys.argv[3])
    except:
        print >> sys.stderr, 'Usage: API_TESTS HOST ITERS [threads]'
        sys.exit(1)
    
    num_threads = 1
    if len(sys.argv) > 4:
        num_threads = int(sys.argv[4])
    
    run_test(api_tests, host, iters, num_threads)

    
