#!/usr/bin/env python2

import google.cloud.storage
import json
import os
import sys

if len(sys.argv) != 4:
    print >> sys.stderr, 'Usage: {} /path/to/service-account.json bucket_name file_path'.format(sys.argv[0])
    sys.exit(1)

service_account_path = sys.argv[1]
bucket_name = sys.argv[2]
snapshot_path = sys.argv[3]

if not os.path.exists(service_account_path):
    print >> sys.stderr, 'No such file or directory: {}'.format(service_account_path)

if not os.path.exists(snapshot_path):
    print >> sys.stderr, 'No such file or directory: {}'.format(snapshot_path)
    sys.exit(1)

storage_client = google.cloud.storage.Client.from_service_account_json(service_account_path)
bucket = storage_client.get_bucket(bucket_name)

path = 'snapshot.bsk'
snapshot = bucket.blob(path)
snapshot.upload_from_filename(snapshot_path)

sys.exit(0)

