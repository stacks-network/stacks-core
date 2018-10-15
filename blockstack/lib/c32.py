#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2018 by Blockstack.org

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

import re
import hashlib
import keylib

C32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
HEX = '0123456789abcdef'

C32_versions = {
    'mainnet': {
        'p2pkh': 22,    # 'P'
        'p2sh': 20      # 'M'
     },
    'testnet': {
        'p2pkh': 26,    # 'T'
        'p2sh': 21      # 'N'
    }
}

ADDR_BITCOIN_TO_STACKS = {
    0: C32_versions['mainnet']['p2pkh'],
    5: C32_versions['mainnet']['p2sh'],
    111: C32_versions['testnet']['p2pkh'],
    196: C32_versions['testnet']['p2sh']
}
    
ADDR_STACKS_TO_BITCOIN = {
    C32_versions['mainnet']['p2pkh']: 0,
    C32_versions['mainnet']['p2sh']: 5,
    C32_versions['testnet']['p2pkh']: 111,
    C32_versions['testnet']['p2sh']: 196
}


def c32normalize(c32input):
    return c32input.upper().replace('O', '0').replace('L', '1').replace('I', '1')


def c32encode(input_hex, min_length=None):
    """
    >>> c32encode('a46ff88886c2ef9762d970b4d2c63678835bd39d')
    'MHQZH246RBQSERPSE2TD5HHPF21NQMWX'
    >>> c32encode('')
    ''
    >>> c32encode('0000000000000000000000000000000000000000', 20)
    '00000000000000000000'
    >>> c32encode('0000000000000000000000000000000000000001', 20)
    '00000000000000000001'
    >>> c32encode('1000000000000000000000000000000000000001', 32)
    '20000000000000000000000000000001'
    >>> c32encode('1000000000000000000000000000000000000000', 32)
    '20000000000000000000000000000000'
    >>> c32encode('1')
    '1'
    >>> c32encode('22')
    '12'
    >>> c32encode('001')
    '01'
    >>> c32encode('0001')
    '01'
    >>> c32encode('00001')
    '001'
    >>> c32encode('000001')
    '001'
    >>> c32encode('10')
    'G'
    >>> c32encode('100')
    '80'
    >>> c32encode('1000')
    '400'
    >>> c32encode('10000')
    '2000'
    >>> c32encode('100000')
    '10000'
    >>> c32encode('1000000')
    'G0000'
    """
    if len(input_hex) == 0:
        return ''

    if not re.match(r'^[0-9a-fA-F]+$', input_hex):
        raise ValueError('Requires a hex string')

    if len(input_hex) % 2 != 0:
        input_hex = '0{}'.format(input_hex)

    input_hex = input_hex.lower()
    
    res = []
    carry = 0
    for i in range(len(input_hex) - 1, -1, -1):
        if (carry < 4):
            current_code = HEX.index(input_hex[i]) >> carry
            next_code = 0
            if i != 0:
                next_code = HEX.index(input_hex[i-1])

            # carry = 0, next_bits is 1, carry = 1, next_bits = 2
            next_bits = 1 + carry
            next_low_bits = (next_code % (1 << next_bits)) << (5 - next_bits)
            cur_c32_digit = C32[current_code + next_low_bits]
            carry = next_bits
            res = [cur_c32_digit] + res
        else:
            carry = 0

    # fix padding
    # -- strip leading c32 zeros
    # -- add leading hex zeros
    c32_leading_zeros = 0
    for i in range(0, len(res)):
        if res[i] != '0':
            break

        c32_leading_zeros += 1

    res = res[c32_leading_zeros:]

    num_leading_hex_zeros = 0
    num_leading_byte_zeros = 0
    for i in range(0, len(input_hex)):
        if input_hex[i] != '0':
            break

        num_leading_hex_zeros += 1

    num_leading_byte_zeros = num_leading_hex_zeros / 2
    res = ['0'] * num_leading_byte_zeros + res

    if min_length > 0:
        count = min_length - len(res)
        if count > 0:
            res = ['0'] * count + res

    return ''.join(res)


def c32decode(c32input, min_length=0):
    """
    >>> c32decode('MHQZH246RBQSERPSE2TD5HHPF21NQMWX')
    'a46ff88886c2ef9762d970b4d2c63678835bd39d'
    >>> c32decode('')
    ''
    >>> c32decode('00000000000000000000', 20)
    '0000000000000000000000000000000000000000'
    >>> c32decode('00000000000000000001', 20)
    '0000000000000000000000000000000000000001'
    >>> c32decode('20000000000000000000000000000001', 20)
    '1000000000000000000000000000000000000001'
    >>> c32decode('20000000000000000000000000000000', 20)
    '1000000000000000000000000000000000000000'
    >>> c32decode('1')
    '01'
    >>> c32decode('12')
    '22'
    >>> c32decode('01')
    '0001'
    >>> c32decode('001')
    '000001'
    >>> c32decode('G')
    '10'
    >>> c32decode('80')
    '0100'
    >>> c32decode('400')
    '1000'
    >>> c32decode('2000')
    '010000'
    >>> c32decode('10000')
    '100000'
    >>> c32decode('G0000')
    '01000000'
    """

    if len(c32input) == 0:
        return ''

    c32input = c32normalize(c32input)
    if not re.match(r'^[' + C32 + ']*$', c32input):
        raise ValueError('Not a c32-encoded string')

    num_leading_zero_bytes = 0
    for i in range(0, len(c32input)):
        if c32input[i] != C32[0]:
            break

        num_leading_zero_bytes += 1

    res = []
    carry = 0
    carry_bits = 0
    for i in range(len(c32input) - 1, -1, -1):
        if carry_bits == 4:
            res = [HEX[carry]] + res
            carry_bits = 0
            carry = 0

        current_code = C32.index(c32input[i]) << carry_bits
        current_value = current_code + carry
        current_hex_digit = HEX[current_value % len(HEX)]

        carry_bits += 1
        carry = current_value >> 4

        if carry > (1 << carry_bits):
            raise Exception('Panic error in decoding')

        res = [current_hex_digit] + res

    # one last carry
    res = [HEX[carry]] + res

    if len(res) % 2 == 1:
        res = [HEX[0]] + res

    # remove all leading zeros while keeping the string even-length
    hex_leading_zeros = 0
    for i in range(0, len(res)):
        if res[i] != '0':
            break

        hex_leading_zeros += 1

    res = res[hex_leading_zeros - (hex_leading_zeros % 2):]
    hexstr = ''.join(res)

    # add back leading zero bytes from the c32 string
    for i in range(0, num_leading_zero_bytes):
        hexstr = '00{}'.format(hexstr)

    if min_length > 0:
        count = min_length * 2 - len(hexstr)
        hexstr = '00' * (count / 2) + hexstr

    return hexstr


def c32checksum(data_hex):
    tmphash = hashlib.sha256(data_hex.decode('hex')).digest()
    data_hash = hashlib.sha256(tmphash).digest()
    checksum = data_hash[0:4].encode('hex')
    return checksum 


def c32checkEncode(version, data):
    """
    >>> c32checkEncode(22, 'a46ff88886c2ef9762d970b4d2c63678835bd39d')
    'P2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7'
    >>> c32checkEncode(0, 'a46ff88886c2ef9762d970b4d2c63678835bd39d')
    '02J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE'
    >>> c32checkEncode(31, 'a46ff88886c2ef9762d970b4d2c63678835bd39d')
    'Z2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR'
    >>> c32checkEncode(11, 'a46ff88886c2ef9762d970b4d2c63678835bd39d')
    'B2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNGTQ5XV'
    >>> c32checkEncode(17, 'a46ff88886c2ef9762d970b4d2c63678835bd39d')
    'H2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPZJKGHG'
    >>> c32checkEncode(2, 'a46ff88886c2ef9762d970b4d2c63678835bd39d')
    '22J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKMQMB2T9'
    >>> c32checkEncode(22, '')
    'P37JJX3D'
    >>> c32checkEncode(22, '0000000000000000000000000000000000000000')
    'P000000000000000000002Q6VF78'
    >>> c32checkEncode(22, '0000000000000000000000000000000000000001')
    'P00000000000000000005JA84HQ'
    >>> c32checkEncode(22, '1000000000000000000000000000000000000001')
    'P80000000000000000000000000000004R0CMNV'
    >>> c32checkEncode(22, '1000000000000000000000000000000000000000')
    'P800000000000000000000000000000033H8YKK'
    >>> c32checkEncode(0, '1')
    '04C407K6'
    >>> c32checkEncode(0, '22')
    '049Q1W6AP'
    >>> c32checkEncode(0, '001')
    '006NZP224'
    >>> c32checkEncode(31, '00001')
    'Z004720442'
    >>> c32checkEncode(31, '000001')
    'Z004720442'
    >>> c32checkEncode(31, '0000001')
    'Z00073C2AR7'
    >>> c32checkEncode(11, '10')
    'B20QX4FW0'
    >>> c32checkEncode(11, '100')
    'B102PC6RCC'
    >>> c32checkEncode(11, '1000')
    'BG02G1QXCQ'
    >>> c32checkEncode(17, '100000')
    'H40003YJA8JD'
    >>> c32checkEncode(17, '1000000')
    'H200001ZTRYYH'
    >>> c32checkEncode(17, '10000000')
    'H1000002QFX7E6'
    >>> c32checkEncode(2, '100000000')
    '2G000003FNKA3P'
    """
    if version < 0 or version >= len(C32):
        raise ValueError('Invalid version -- must be between 0 and {}'.format(len(C32)-1))

    if not re.match(r'^[0-9a-fA-F]*$', data):
        raise ValueError('Invalid data -- must be hex')

    data = data.lower()
    if len(data) % 2 != 0:
        data = '0{}'.format(data)

    version_hex = '{:02x}'.format(version)
    checksum_hex = c32checksum('{}{}'.format(version_hex, data))
    c32str = c32encode('{}{}'.format(data, checksum_hex))
    return '{}{}'.format(C32[version], c32str)


def c32checkDecode(c32data):
    """
    >>> c32checkDecode('P2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7')
    (22, 'a46ff88886c2ef9762d970b4d2c63678835bd39d')
    >>> c32checkDecode('02J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE')
    (0, 'a46ff88886c2ef9762d970b4d2c63678835bd39d')
    >>> c32checkDecode('Z2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR')
    (31, 'a46ff88886c2ef9762d970b4d2c63678835bd39d')
    >>> c32checkDecode('B2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNGTQ5XV')
    (11, 'a46ff88886c2ef9762d970b4d2c63678835bd39d')
    >>> c32checkDecode('H2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPZJKGHG')
    (17, 'a46ff88886c2ef9762d970b4d2c63678835bd39d')
    >>> c32checkDecode('22J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKMQMB2T9')
    (2, 'a46ff88886c2ef9762d970b4d2c63678835bd39d')
    >>> c32checkDecode('P37JJX3D')
    (22, '')
    >>> c32checkDecode('P000000000000000000002Q6VF78')
    (22, '0000000000000000000000000000000000000000')
    >>> c32checkDecode('P00000000000000000005JA84HQ')
    (22, '0000000000000000000000000000000000000001')
    >>> c32checkDecode('P80000000000000000000000000000004R0CMNV')
    (22, '1000000000000000000000000000000000000001')
    >>> c32checkDecode('P800000000000000000000000000000033H8YKK')
    (22, '1000000000000000000000000000000000000000')
    >>> c32checkDecode('04C407K6')
    (0, '01')
    >>> c32checkDecode('049Q1W6AP')
    (0, '22')
    >>> c32checkDecode('006NZP224')
    (0, '0001')
    >>> c32checkDecode('Z004720442')
    (31, '000001')
    >>> c32checkDecode('Z00073C2AR7')
    (31, '00000001')
    >>> c32checkDecode('B20QX4FW0')
    (11, '10')
    >>> c32checkDecode('B102PC6RCC')
    (11, '0100')
    >>> c32checkDecode('BG02G1QXCQ')
    (11, '1000')
    >>> c32checkDecode('H40003YJA8JD')
    (17, '100000')
    >>> c32checkDecode('H200001ZTRYYH')
    (17, '01000000')
    >>> c32checkDecode('H1000002QFX7E6')
    (17, '10000000')
    >>> c32checkDecode('2G000003FNKA3P')
    (2, '0100000000')
    """
    if not re.match(r'^[' + C32 + ']*$', c32data):
        raise ValueError('Must be c32 data')

    c32data = c32normalize(c32data)
    data_hex = c32decode(c32data[1:])

    if len(data_hex) < 8:
        raise ValueError('Not a c32check string')

    version_chr = c32data[0]
    version = C32.index(version_chr)
    version_hex = '{:02x}'.format(version)
    checksum = data_hex[-8:]

    if c32checksum('{}{}'.format(version_hex, data_hex[0:len(data_hex)-8])) != checksum:
        raise ValueError('Invalid c32check string: checksum mismatch')

    return (version, data_hex[0:len(data_hex)-8])


def c32address(version, hash160hex):
    """
    >>> c32address(22, 'a46ff88886c2ef9762d970b4d2c63678835bd39d')
    'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7'
    >>> c32address(0, '0000000000000000000000000000000000000000')
    'S0000000000000000000002AA028H'
    >>> c32address(31, '0000000000000000000000000000000000000001')
    'SZ00000000000000000005HZ3DVN'
    >>> c32address(20, '1000000000000000000000000000000000000001')
    'SM80000000000000000000000000000004WBEWKC'
    >>> c32address(26, '1000000000000000000000000000000000000000')
    'ST80000000000000000000000000000002YBNPV3'
    """
    if not re.match(r'^[0-9a-fA-F]{40}$', hash160hex):
        raise ValueError('Invalid argument: not a hash160 hex string')

    c32string = c32checkEncode(version, hash160hex)
    return 'S{}'.format(c32string)


def c32addressDecode(c32addr):
    """
    >>> c32addressDecode('SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7')
    (22, 'a46ff88886c2ef9762d970b4d2c63678835bd39d')
    >>> c32addressDecode('S0000000000000000000002AA028H')
    (0, '0000000000000000000000000000000000000000')
    >>> c32addressDecode('SZ00000000000000000005HZ3DVN')
    (31, '0000000000000000000000000000000000000001')
    >>> c32addressDecode('SM80000000000000000000000000000004WBEWKC')
    (20, '1000000000000000000000000000000000000001')
    >>> c32addressDecode('ST80000000000000000000000000000002YBNPV3')
    (26, '1000000000000000000000000000000000000000')
    """
    if (len(c32addr) <= 5):
        raise ValueError('Invalid c32 address: invalid length')

    return c32checkDecode(c32addr[1:])


def b58ToC32(b58check, version=-1):
    """
    >>> b58ToC32('1FzTxL9Mxnm2fdmnQEArfhzJHevwbvcH6d')
    'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7'
    >>> b58ToC32('3GgUssdoWh5QkoUDXKqT6LMESBDf8aqp2y')
    'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G'
    >>> b58ToC32('mvWRFPELmpCHSkFQ7o9EVdCd9eXeUTa9T8')
    'ST2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQYAC0RQ'
    >>> b58ToC32('2N8EgwcZq89akxb6mCTTKiHLVeXRpxjuy98')
    'SN2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKP6D2ZK9'
    >>> b58ToC32('1FzTxL9Mxnm2fdmnQEArfhzJHevwbvcH6d', 22)
    'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7'
    >>> b58ToC32('1FzTxL9Mxnm2fdmnQEArfhzJHevwbvcH6d', 0)
    'S02J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE'
    >>> b58ToC32('1FzTxL9Mxnm2fdmnQEArfhzJHevwbvcH6d', 31)
    'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR'
    >>> b58ToC32('1FzTxL9Mxnm2fdmnQEArfhzJHevwbvcH6d', 20)
    'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G'
    >>> b58ToC32('1FzTxL9Mxnm2fdmnQEArfhzJHevwbvcH6d', 26)
    'ST2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQYAC0RQ'
    >>> b58ToC32('1FzTxL9Mxnm2fdmnQEArfhzJHevwbvcH6d', 21)
    'SN2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKP6D2ZK9'
    """
    addr_version_byte, addr_bin, addr_checksum = keylib.b58check.b58check_unpack(b58check)
    addr_version = ord(addr_version_byte)
    addr_hash160 = addr_bin.encode('hex')

    stacks_version = None
    if version < 0:
        stacks_version = addr_version
        if ADDR_BITCOIN_TO_STACKS.get(addr_version) is not None:
            stacks_version = ADDR_BITCOIN_TO_STACKS[addr_version]

    else:
        stacks_version = version

    return c32address(stacks_version, addr_hash160)


def c32ToB58(c32string, version=-1):
    """
    >>> c32ToB58('SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7')
    '1FzTxL9Mxnm2fdmnQEArfhzJHevwbvcH6d'
    >>> c32ToB58('SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G')
    '3GgUssdoWh5QkoUDXKqT6LMESBDf8aqp2y'
    >>> c32ToB58('ST2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQYAC0RQ')
    'mvWRFPELmpCHSkFQ7o9EVdCd9eXeUTa9T8'
    >>> c32ToB58('SN2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKP6D2ZK9')
    '2N8EgwcZq89akxb6mCTTKiHLVeXRpxjuy98'
    >>> c32ToB58('SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7', 0)
    '1FzTxL9Mxnm2fdmnQEArfhzJHevwbvcH6d'
    >>> c32ToB58('SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7', 5)
    '3GgUssdoWh5QkoUDXKqT6LMESBDf8aqp2y'
    >>> c32ToB58('SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7', 111)
    'mvWRFPELmpCHSkFQ7o9EVdCd9eXeUTa9T8'
    >>> c32ToB58('SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7', 196)
    '2N8EgwcZq89akxb6mCTTKiHLVeXRpxjuy98'
    """
    addr_version, addr_hash160 = c32addressDecode(c32string)

    bitcoin_version = None
    if version < 0:
        bitcoin_version = addr_version
        if ADDR_STACKS_TO_BITCOIN.get(addr_version) is not None:
            bitcoin_version = ADDR_STACKS_TO_BITCOIN[addr_version]

    else:
        bitcoin_version = version

    return keylib.b58check.b58check_encode(addr_hash160.decode('hex'), bitcoin_version)
