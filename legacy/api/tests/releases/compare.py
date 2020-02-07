#!/usr/bin/env python2

import os
import sys
import requests
import json

WARN = False

def parse_api_list(data):
    # data is a series of lines with API calls
    # empty lines are permitted
    # line fragments after a '#' are considered comments
    return filter(lambda l: len(l) > 0, [l2.strip().split('#')[0].strip() for l2 in data.split('\n')])
    

def compare_call(route, host1, host2):
    print 'check {}'.format(route)
    try:
        r1 = requests.get(host1 + route)
        r2 = requests.get(host2 + route)

        assert r1.status_code < 500 and r2.status_code < 500, 'GET {} status code {}, {} status code {}'.format(host1 + route, r1.status_code, host2 + route, r2.status_code)

        try:
            res1 = r1.json()
        except:
            raise AssertionError('Response from {} is not JSON'.format(host1 + route))

        try:
            res2 = r2.json()
        except:
            raise AssertionError('Response from {} is not JSON'.format(host2 + route))

        assert r1.status_code == r2.status_code, 'Status code mismatch: {} returned {}; {} returned {}'.format(host1 + route, r1.status_code, host2 + route, r2.status_code)
        assert r1.status_code < 300 or r1.status_code > 399, 'Invalid status code: got {}'.format(r1.status_code)

        if r1.status_code >= 400:
            if 'error' in res1:
                assert 'error' in res2, 'Missing error in {}: {}'.format(host2 + route, res2)

                if res1['error'] != res2['error'] and WARN:
                    print >> sys.stderr, 'WARN: Mismatch error on {}: "{}" != "{}"'.format(route, res1['error'], res2['error'])

                return True
            
        # r2 must contain r1
        missing = []
        incorrect = []
        if isinstance(res1, list):
            assert isinstance(res2, list), 'Type mismatch: {} returns list, {} returns {}'.format(host1 + route, host2 + route, type(res2))
            
            # don't have to be in the same order, but must have the same elements 
            res1.sort()
            res2.sort()
            assert res1 == res2, 'Unequal lists: {} returns {}, {} returns {}'.format(host1 + route, res1, host2 + route, res2)

        elif isinstance(res1, dict):
            assert isinstance(res2, dict), 'Type mismatch: {} returns dict, {} returns {}'.format(host1 + route, host2 + route, type(res2))

            for k in res1:
                if k not in res2:
                    missing.append(k)
                    continue

                if res2[k] != res1[k]:
                    incorrect.append(k)
                    continue
                    
            if len(missing) > 0 or len(incorrect) > 0:
                missing_str = ','.join(missing) if len(missing) > 0 else '(none)'
                incorrect_str = ','.join(['{} ({} != {})'.format(k, json.dumps(res1[k], indent=4, sort_keys=True), json.dumps(res2[k], indent=4, sort_keys=True)) for k in incorrect]) if len(incorrect) > 0 else '(none)'
                raise AssertionError('Response from {} does not match {}: missing: {}, incorrect: {}'.format(host2 + route, host1 + route, missing_str, incorrect_str))

        elif isinstance(res1, int) or isinstance(res2, float) or isinstance(res2, long):
            assert res1 == res2, 'Unequal number: {} returns {}, {} returns {}'.format(host1 + route, res1, host2 + route, res2)

        return True

    except AssertionError as ae:
        print >> sys.stderr, 'ERROR: {}'.format(ae.message)
        return False
         

def run_test(path, host1, host2):
    rc = True
    with open(path, 'r') as f:
        data = f.read()
        api_calls = parse_api_list(data)
        for api_call in api_calls:
            rc2 = compare_call(api_call, host1, host2)
            rc = rc and rc2

    return rc
    
if __name__ == '__main__':
    try:
        api_tests = sys.argv[1]
        host1 = sys.argv[2]
        host2 = sys.argv[3]
    except:
        print >> sys.stderr, 'Usage: API_TESTS HOST1 HOST2'
        sys.exit(1)

    rc = run_test(api_tests, host1, host2)
    sys.exit(0 if rc else 1)

    
