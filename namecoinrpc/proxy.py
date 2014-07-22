# -*- coding: utf-8 -*-
#-----------------------
#    Open Name System
#    ~~~~~
#
#    :copyright: (c) 2014 by opennamesystem.org
#    :license: MIT, see LICENSE for more details.
#-----------------------
# Previous copyright, from bitcoin-python:

"""
  Copyright 2011 Jeff Garzik

  AuthServiceProxy has the following improvements over python-jsonrpc's
  ServiceProxy class:

  - HTTP connections persist for the life of the AuthServiceProxy object
    (if server supports HTTP/1.1)
  - sends protocol 'version', per JSON-RPC 1.1
  - sends proper, incrementing 'id'
  - sends Basic HTTP authentication headers
  - parses all JSON numbers that look like floats as Decimal
  - uses standard Python json lib

  Previous copyright, from python-jsonrpc/jsonrpc/proxy.py:

  Copyright (c) 2007 Jan-Klaas Kollhof

  This file is part of jsonrpc.

  jsonrpc is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  This software is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this software; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
"""

try:
    import http.client as httplib
except ImportError:
    import httplib
import base64
import json
import decimal
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

USER_AGENT = "AuthServiceProxy/0.1"

HTTP_TIMEOUT = 30


class JSONRPCException(Exception):
    def __init__(self, rpcError):
        Exception.__init__(self)
        self.error = rpcError


class AuthServiceProxy(object):
    def __init__(self, serviceURL, serviceName=None):
        self.__serviceURL = serviceURL
        self.__serviceName = serviceName
        self.__url = urlparse.urlparse(serviceURL)
        if self.__url.port is None:
            port = 80
        else:
            port = self.__url.port
        self.__idcnt = 0
        authpair = "%s:%s" % (self.__url.username, self.__url.password)
        authpair = authpair.encode('utf8')
        self.__authhdr = "Basic ".encode('utf8') + base64.b64encode(authpair)
        if self.__url.scheme == 'https':
            self.__conn = httplib.HTTPSConnection(self.__url.hostname, port, None, None,False,
                                             HTTP_TIMEOUT)
        else:
            self.__conn = httplib.HTTPConnection(self.__url.hostname, port, False,
                                             HTTP_TIMEOUT)

    def __getattr__(self, name):
        if self.__serviceName != None:
            name = "%s.%s" % (self.__serviceName, name)
        return AuthServiceProxy(self.__serviceURL, name)

    def __call__(self, *args):
         self.__idcnt += 1

         postdata = json.dumps({
                'version': '1.1',
                'method': self.__serviceName,
                'params': args,
                'id': self.__idcnt})
         self.__conn.request('POST', self.__url.path, postdata,
                 { 'Host' : self.__url.hostname,
                  'User-Agent' : USER_AGENT,
                  'Authorization' : self.__authhdr,
                  'Content-type' : 'application/json' })

         httpresp = self.__conn.getresponse()
         if httpresp is None:
             raise JSONRPCException({
                     'code' : -342, 'message' : 'missing HTTP response from server'})

         resp = httpresp.read()
         resp = resp.decode('utf8')
         resp = json.loads(resp, parse_float=decimal.Decimal)
         if 'error' in resp and resp['error'] != None:
             raise JSONRPCException(resp['error'])
         elif 'result' not in resp:
             raise JSONRPCException({
                     'code' : -343, 'message' : 'missing JSON-RPC result'})
         else:
             return resp['result']

    def _batch(self, rpc_call_list):
         postdata = json.dumps(list(rpc_call_list))
         self.__conn.request('POST', self.__url.path, postdata,
                 { 'Host' : self.__url.hostname,
                  'User-Agent' : USER_AGENT,
                  'Authorization' : self.__authhdr,
                  'Content-type' : 'application/json' })

         httpresp = self.__conn.getresponse()
         if httpresp is None:
             raise JSONRPCException({
                     'code' : -342, 'message' : 'missing HTTP response from server'})

         resp = httpresp.read()
         resp = resp.decode('utf8')
         resp = json.loads(resp, parse_float=decimal.Decimal)
         return resp
