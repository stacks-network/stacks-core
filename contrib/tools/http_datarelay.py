#!/usr/bin/env python3
import sys, os, socket, time
from urllib.parse import urlparse, parse_qs
from socketserver import ThreadingMixIn
from http.server import SimpleHTTPRequestHandler, HTTPServer
from collections import defaultdict

HOST = socket.gethostname()
PORT = 8080
highwaters = defaultdict(lambda: -1)
queue = []

class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    pass

class MyHTTPRequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        frag = urlparse(self.path)
        q = parse_qs(frag.query)
        node_id = q['id'][0]
        print(f"connected client {node_id} highwater {highwaters[node_id]}")
        msgs = msgs_since(highwaters[node_id])
        print(f"sending {len(msgs)} msgs to id {node_id}")
        self.send_response(200)
        self.end_headers()
        if len(msgs) > 0:
            next_msg = msgs[0]
            self.wfile.write(next_msg)
            highwaters[node_id] += 1
            print(f"sent msg #{highwaters[node_id]} ({len(next_msg)})")

    def do_POST(self):
        contentLength = int(self.headers['Content-Length'])
        msg = self.rfile.read(contentLength)
        queue.append(msg)
        print(f"posted {msg} ({contentLength}) id {len(queue)} {type(msg)}")
        self.send_response(200)
        self.end_headers()

def msgs_since(highwater):
    if highwater == -1:
        first_unread = 0
    else:
        first_unread = highwater + 1
    return queue[first_unread:]        

server = ThreadingSimpleServer(('0.0.0.0', PORT), MyHTTPRequestHandler)
print("Serving HTTP from", HOST, "using port", PORT)
try:
    while 1:
        sys.stdout.flush()
        server.handle_request()
except KeyboardInterrupt:
    print("\nShutting down server per users request.")