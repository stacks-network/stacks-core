#!/bin/bash

curl 'http://127.0.0.1:9776/?id=1'
curl 'http://127.0.0.1:9776/?id=3'
curl 'http://127.0.0.1:9776' -X POST -d 'Msg # 0'
curl 'http://127.0.0.1:9776/?id=1'
curl 'http://127.0.0.1:9776/?id=5'
curl 'http://127.0.0.1:9776/?id=4'
curl 'http://127.0.0.1:9776/?id=1'
curl 'http://127.0.0.1:9776' -X POST -d 'Msg # 1'
curl 'http://127.0.0.1:9776/?id=1'
curl 'http://127.0.0.1:9776/?id=3'
curl 'http://127.0.0.1:9776/?id=5'
curl 'http://127.0.0.1:9776' -X POST -d 'Msg # 2'
curl 'http://127.0.0.1:9776/?id=1'
curl 'http://127.0.0.1:9776/?id=4'
curl 'http://127.0.0.1:9776/?id=4'
# try an empty message
curl 'http://127.0.0.1:9776' -X POST
curl 'http://127.0.0.1:9776/?id=1'
# try invalid GET
curl 'http://127.0.0.1:9776'
curl 'http://127.0.0.1:9776/?z=5&f=6'
curl 'http://127.0.0.1:9776/?za'