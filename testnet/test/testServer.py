#!/usr/bin/env python2

import os
import posixpath
import BaseHTTPServer
import urllib
import cgi
import sys
import shutil
import mimetypes
import requests
import json
import time
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

UPSTREAM = "http://localhost:30001"

UPSTREAM_GET_PATHS = ['/config', '/operations', '/atlas-neighbors', '/blockHeight', '/balance/', '/names/', '/namespaces/']
UPSTREAM_POST_PATHS = ['/sendBTC', '/sendStacks', '/registerName', '/registerSubdomain']

MOCK = os.environ.get('MOCK')

# lifted from SimpleHTTPServer
class TestnetTestServerHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def get_data(self):
        contentlen = int(self.headers.getheader('content-length', 0))
        bits = self.rfile.read(contentlen)
        return bits

    def reply_json(self, ret, cache_max_age=None):

        ret = json.dumps(ret)
        self.send_response(200)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', len(ret))

        if cache_max_age:
            self.send_header('cache-control', 'max-age={}'.format(cache_max_age))

        self.end_headers()
        self.wfile.write(ret)
        return


    def do_GET(self):
        """Serve a GET request."""
        if MOCK:
            if self.path == '/config':
                ret = {
                    'gaiaReadURL': 'http://mock-testnet.blockstack.org:4000',
                    'gaiaWriteURL': 'http://mock-testnet.blockstack.org:4001',
                    'subdomainRegistrarURL': 'http://mock-testnet.blockstack.org:30000',
                    'transactionBroadcasterURL': 'http://mock-testnet.blockstack.org:16269',
                    'bitcoinJSONRPCURL': 'http://mock-testnet.blockstack.org:18332',
                    'bitcoinP2PURL': 'http://mock-testnet.blockstack.org:18444'
                }
                return self.reply_json(ret, 3600)

            if self.path == '/blockHeight':
                ret = {'blockHeight': str(int(time.time())), 'consensusHash': os.urandom(16).encode('hex')}
                return self.reply_json(ret, 60)

            if self.path == "/operations":
                ret = []
                ret.append({'opcode': 'NAME_PREORDER', 'op_fee': 60000, 'address': '16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg', 'txid': os.urandom(32).encode('hex')})
                ret.append({'opcode': 'NAME_REGISTER', 'namespace_id': 'id', 'name': 'judecn.id', 'address': '16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg', 'txid': os.urandom(32).encode('hex')})
                ret.append({'opcode': 'TOKEN_TRANSFER', 'token_fee': 100000000, 'address': '16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg', 'txid': os.urandom(32).encode('hex')})
                return self.reply_json(ret, 60)

            if self.path == "/atlas-neighbors":
                ret = []
                ret.append({'host': 'localhost', 'port': 1234})
                ret.append({'host': 'www.foo.com', 'port': 1234})
                ret.append({'host': 'www.asdf.com', 'port': 1234})
                return self.reply_json(ret, 60)

            if self.path.startswith('/balance/'):
                ret = {'btc': 123, 'stacks': 1234}
                return self.reply_json(ret, 60)

            if self.path.startswith('/names/'):
                ret = ['larry.id', 'curly.podcast', 'moe.helloworld']
                return self.reply_json(ret, 60)

            if self.path.startswith('/namespaces/'):
                ret = ['id', 'helloworld', 'podcast']
                return self.reply_json(ret, 60)

        for upstream_path in UPSTREAM_GET_PATHS:
            if self.path.startswith(upstream_path):
                req = requests.get(
                        url=UPSTREAM + self.path,
                        headers={key: self.headers[key] for key in self.headers if key != 'Host'},
                        data=self.get_data(),
                        allow_redirects=False)
                
                excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
                headers = dict([(name, value) for (name, value) in req.raw.headers.items()
                           if name.lower() not in excluded_headers])

                self.send_response(req.status_code)
                for h in headers:
                    self.send_header(h, headers[h])

                self.send_header('content-length', len(req.content))

                self.end_headers()
                self.wfile.write(req.content)
                return

        f = self.send_head()
        if f:
            self.copyfile(f, self.wfile)
            f.close()


    def do_POST(self):
        """Serve a POST request."""
        if self.path in UPSTREAM_POST_PATHS:
            content_type = self.headers.getheader('content-type')
            req = requests.post(
                    url=UPSTREAM + self.path,
                    headers={key: self.headers[key] for key in self.headers if key != 'Host'},
                    data=self.get_data(),
                    allow_redirects=False)

            excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
            headers = dict([(name, value) for (name, value) in req.raw.headers.items()
                       if name.lower() not in excluded_headers])

            self.send_response(req.status_code)
            for h in headers:
                self.send_header(h, headers[h])

            self.send_header('content-length', len(req.content))

            self.end_headers()
            self.wfile.write(req.content)
            return

        return self.send_response(404)


    def do_HEAD(self):
        """Serve a HEAD request."""
        f = self.send_head()
        if f:
            f.close()

    def send_head(self):
        """Common code for GET and HEAD commands.
        This sends the response code and MIME headers.
        Return value is either a file object (which has to be copied
        to the outputfile by the caller unless the command was HEAD,
        and must be closed by the caller under all circumstances), or
        None, in which case the caller has nothing further to do.
        """
        path = self.translate_path(self.path)
        f = None
        if os.path.isdir(path):
            if not self.path.endswith('/'):
                # redirect browser - doing basically what apache does
                self.send_response(301)
                self.send_header("Location", self.path + "/")
                self.end_headers()
                return None
            for index in "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
            else:
                return self.list_directory(path)
        ctype = self.guess_type(path)
        try:
            # Always read in binary mode. Opening files in text mode may cause
            # newline translations, making the actual size of the content
            # transmitted *less* than the content-length!
            f = open(path, 'rb')
        except IOError:
            self.send_error(404, "File not found")
            return None
        self.send_response(200)
        self.send_header("Content-type", ctype)
        fs = os.fstat(f.fileno())
        self.send_header("Content-Length", str(fs[6]))
        self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
        self.end_headers()
        return f

    def list_directory(self, path):
        """Helper to produce a directory listing (absent index.html).
        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().
        """
        try:
            list = os.listdir(path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return None
        list.sort(key=lambda a: a.lower())
        f = StringIO()
        displaypath = cgi.escape(urllib.unquote(self.path))
        f.write('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
        f.write("<html>\n<title>Directory listing for %s</title>\n" % displaypath)
        f.write("<body>\n<h2>Directory listing for %s</h2>\n" % displaypath)
        f.write("<hr>\n<ul>\n")
        for name in list:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                displayname = name + "@"
                # Note: a link to a directory displays with @ and links with /
            f.write('<li><a href="%s">%s</a>\n'
                    % (urllib.quote(linkname), cgi.escape(displayname)))
        f.write("</ul>\n<hr>\n</body>\n</html>\n")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        encoding = sys.getfilesystemencoding()
        self.send_header("Content-type", "text/html; charset=%s" % encoding)
        self.send_header("Content-Length", str(length))
        self.end_headers()
        return f

    def translate_path(self, path):
        """Translate a /-separated PATH to the local filename syntax.
        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)
        """
        # abandon query parameters
        path = path.split('?',1)[0]
        path = path.split('#',1)[0]
        path = posixpath.normpath(urllib.unquote(path))
        words = path.split('/')
        words = filter(None, words)
        path = os.getcwd()
        for word in words:
            drive, word = os.path.splitdrive(word)
            head, word = os.path.split(word)
            if word in (os.curdir, os.pardir): continue
            path = os.path.join(path, word)
        return path

    def copyfile(self, source, outputfile):
        """Copy all data between two file objects.
        The SOURCE argument is a file object open for reading
        (or anything with a read() method) and the DESTINATION
        argument is a file object open for writing (or
        anything with a write() method).
        The only reason for overriding this would be to change
        the block size or perhaps to replace newlines by CRLF
        -- note however that this the default server uses this
        to copy binary data as well.
        """
        shutil.copyfileobj(source, outputfile)

    def guess_type(self, path):
        """Guess the type of a file.
        Argument is a PATH (a filename).
        Return value is a string of the form type/subtype,
        usable for a MIME Content-type header.
        The default implementation looks the file's extension
        up in the table self.extensions_map, using application/octet-stream
        as a default; however it would be permissible (if
        slow) to look inside the data to make a better guess.
        """

        base, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        else:
            return self.extensions_map['']

    if not mimetypes.inited:
        mimetypes.init() # try to read system mime.types
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'application/octet-stream', # Default
        '.py': 'text/plain',
        '.c': 'text/plain',
        '.h': 'text/plain',
        })


def test(HandlerClass = TestnetTestServerHandler,
         ServerClass = BaseHTTPServer.HTTPServer):
    BaseHTTPServer.test(HandlerClass, ServerClass)


if __name__ == '__main__':
    test()
