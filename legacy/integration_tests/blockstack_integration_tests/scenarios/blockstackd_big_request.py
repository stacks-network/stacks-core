#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
""" 
"""
TEST ENV BLOCKSTACK_TEST_MAX_RPC_LEN 81920
"""

import testlib 
import json
import blockstack
import virtualchain
import binascii
import socket
import base64
import xmlrpclib
import StringIO
import gzip

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"


def make_xml_call(msg_len, gzipped=False):
    content_type = 'text/xml'

    if gzipped:
        content_type = 'application/gzip'
    
    content_encoding_str = ""
    if gzipped:
        content_encoding_str = "Content-Encoding: gzip\r\n"

    xml_part_http = ("POST /RPC2 HTTP/1.1\r\n"
                     "Host: localhost:" + str(blockstack.RPC_SERVER_PORT) + "\r\n"
                     "User-Agent: curl/7.56.0\r\n"
                     "Accept: */*\r\n"
                     "Content-Type: " + content_type + "\r\n" + content_encoding_str + \
                     "Content-Length: {}\r\n\r\n")

    xml_part_header = "<?xml version='1.0'?><methodCall><methodName>get_blockstack_ops_hash_at</methodName><params><param><value><integer>"
    xml_part_trailer = "</integer></param></params></methodCall></xml>"
    xml_part_payload = '0' * msg_len
    
    xml_part_body = xml_part_header + xml_part_payload + xml_part_trailer
    xml_part_msg = xml_part_http.format(msg_len) + xml_part_body

    i = 0
    while len(xml_part_body) > msg_len:
        xml_part_body = xml_part_header + xml_part_payload[i:] + xml_part_trailer
        if gzipped:
            out = StringIO.StringIO()
            with gzip.GzipFile(fileobj=out, mode='w') as f:
                f.write(xml_part_body)

            xml_part_body = out.getvalue()

        xml_part_msg = xml_part_http.format(len(xml_part_body)) + xml_part_body
        i += 1

    if not gzipped:
        assert len(xml_part_body) == msg_len, len(xml_part_body)
    else:
        assert len(xml_part_body) < msg_len, len(xml_part_body)

    return xml_part_msg


def scenario( wallets, **kw ):

    # valid 500kb + 1 XMLRPC, should be rejected
    xmlmsg = make_xml_call(512 * 1024 + 1)

    print '\ntest too big\n'

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("localhost", blockstack.RPC_SERVER_PORT))
    s.send(xmlmsg)
    buf = s.recv(16384)

    if 'HTTP/1.0 400' not in buf:
        print buf
        return False
    
    # valid 500kb + 1 XMLRPC gzipp'ed, should be rejected
    xmlmsg = make_xml_call(512 * 1024 + 1, gzipped=True)

    print '\ntest too big, gzipped\n'

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("localhost", blockstack.RPC_SERVER_PORT))
    s.send(xmlmsg)
    buf = s.recv(16384)

    if 'HTTP/1.0 501' not in buf:
        print buf
        return False

    # valid 500kb XMLRPC, should be accepted
    xmlmsg = make_xml_call(512 * 1024)

    print '\ntest just big enough\n'

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("localhost", blockstack.RPC_SERVER_PORT))
    s.send(xmlmsg)
    buf = s.recv(16384)

    if 'HTTP/1.0 200' not in buf:
        print buf
        return False

    # valid 500kb XMLRPC gzipped, should be rejected
    xmlmsg = make_xml_call(512 * 1024, gzipped=True)

    print '\ntest just big enough, gzipped\n'

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("localhost", blockstack.RPC_SERVER_PORT))
    s.send(xmlmsg)
    buf = s.recv(16384)

    if 'HTTP/1.0 501' not in buf:
        print buf
        return False

    big_zonefile = '0' * 40960
    big_zonefile_2 = '1' * 40960
    big_zonefile_nack = '2' * 40961

    # make some zonefiles
    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    zonefile_hash = blockstack.lib.storage.get_zonefile_data_hash(big_zonefile)
    testlib.blockstack_name_update("foo.test", zonefile_hash, wallets[3].privkey)
    testlib.next_block(**kw)

    srv = xmlrpclib.ServerProxy("http://localhost:{}".format(blockstack.RPC_SERVER_PORT))
    res = srv.put_zonefiles([base64.b64encode(big_zonefile)])
    res = json.loads(res)
    if 'error' in res:
        print 'failed to put {}'.format(zonefile_hash)
        print res
        return False

    # ask for zonefile
    res = srv.get_zonefiles([zonefile_hash])
    res = json.loads(res)
    if 'error' in res:
        print 'failed to get {}'.format(zonefile_hash)
        print res
        return False

    zonefile_hash_2 = blockstack.lib.storage.get_zonefile_data_hash(big_zonefile_2)
    testlib.blockstack_name_update("foo.test", zonefile_hash_2, wallets[3].privkey)
    testlib.next_block(**kw)

    res = srv.put_zonefiles([base64.b64encode(big_zonefile_2)])
    res = json.loads(res)
    if 'error' in res:
        print 'failed to put {}'.format(zonefile_hash_2)
        print res
        return False
 
    # ask for zonefile
    res = srv.get_zonefiles([zonefile_hash_2])
    res = json.loads(res)
    if 'error' in res:
        print 'failed to get {}'.format(zonefile_hash_2)
        print res
        return False

    zonefile_hash_nack = blockstack.lib.storage.get_zonefile_data_hash(big_zonefile_nack)
    testlib.blockstack_name_update("foo.test", zonefile_hash_nack, wallets[3].privkey)
    testlib.next_block(**kw)

    res = srv.put_zonefiles([base64.b64encode(big_zonefile_nack)])
    res = json.loads(res)
    if 'error' in res:
        print 'failed to put {}'.format(zonefile_hash_nack)
        print res
        return False

    if res['saved'][0] != 0:
        print 'accidentally saved {}'.format(zonefile_hash_nack)
        print res
        return False

    # should be unavailable 
    res = srv.get_zonefiles([zonefile_hash_nack])
    res = json.loads(res)
    if 'error' in res:
        print 'failed to query'
        print res
        return False

    if len(res['zonefiles']) > 0:
        print 'accidentally fetched big zonefile'
        print res
        return False

    # should fail, since the RPC was too big
    try:
        res = srv.get_zonefiles([zonefile_hash, zonefile_hash_2])
            
        print 'accidentally exceeded RPC'
        print res
        return False
    except ValueError as ve:
        # should be a value error from defusedxml
        pass
    except Exception:
        raise
    

def check( state_engine ):
    
    return True

