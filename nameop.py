# -*- coding: utf-8 -*-
"""
    Bitname
    ~~~~~

    :copyright: (c) 2014 by Halfmoon Labs
    :license: MIT, see LICENSE for more details.
"""

import os, binascii, string
from coinkit import bin_hash160
from utilitybelt import is_hex, change_charset

class Opcode():
	PREORDER = 'P'
	CLAIM = 'C'
	UPDATE = 'U'
	TRANSFER = 'T'

LENGTHS = {
	'prefix': 1,
	'name_hash': 20,
	'prev_block_hash': 19,
	'name': 19,
	'salt': 16,
	'update_hash': 20,
}

PADDING_BYTE = '\x00'

def gen_salt():
	return os.urandom(LENGTHS['salt'])

B37_CHARS = string.digits + string.lowercase + '-'
B38_CHARS = string.digits + string.lowercase + '-.'
B16_CHARS = string.hexdigits[0:16]

def b38_to_bin(s):
	s_b16 = change_charset(s, B38_CHARS, B16_CHARS)
	return binascii.unhexlify(s_b16)

def bin_to_b38(s):
	s_b16 = binascii.hexlify(s)
	return change_charset(s_b16, B16_CHARS, B38_CHARS)

def parse_nameop(data):
	if is_hex(data) and len(data) <= 80:
		hex_encoding = data
		binary_encoding = hex_encoding.decode('hex')
	elif len(data) <= 40:
		binary_encoding = data
		hex_encoding = binary_encoding.encode('hex')
	else:
		raise ValueError("Data encoding must be in proper hex or binary format.")

	opcode = binary_encoding[0]
	if opcode not in ['P','C','U','T']:
		raise ValueError("ASCII encoding must have a valid opcode.")

	if opcode == 'P':
		name_hash = binary_encoding[LENGTHS['prefix']:LENGTHS['prefix']+LENGTHS['name_hash']]
		prev_block_hash = binary_encoding[LENGTHS['prefix']+LENGTHS['name_hash']:LENGTHS['prefix']+LENGTHS['name_hash']+LENGTHS['prev_block_hash']]
		nameop = PreorderNameOp(name_hash, prev_block_hash)
	elif opcode == 'C':
		name = binary_encoding[LENGTHS['prefix']:LENGTHS['prefix']+LENGTHS['name']]
		salt = binary_encoding[LENGTHS['prefix']+LENGTHS['name']:LENGTHS['prefix']+LENGTHS['name']+LENGTHS['salt']]
		nameop = ClaimNameOp(name, salt)
	elif opcode == 'U':
		name = binary_encoding[LENGTHS['prefix']:LENGTHS['prefix']+LENGTHS['name']]
		update_hash = binary_encoding[LENGTHS['prefix']+LENGTHS['name']:LENGTHS['prefix']+LENGTHS['name']+LENGTHS['update_hash']]
		nameop = UpdateNameOp(name, update_hash)
	elif opcode == 'T':
		name = binary_encoding[LENGTHS['prefix']:LENGTHS['prefix']+LENGTHS['name']]
		nameop = TransferNameOp(name)

	return nameop

class NameOp():
	def __init__(self, opcode):
		raise Exception('Not implemented!')

	def packed_name(self):
		if hasattr(self, 'name'):
			return self.name.rjust(LENGTHS['name'], PADDING_BYTE)
		return None

	def to_bin(self):
		raise Exception('Not implemented!')

	def to_hex(self):
		return self.to_bin().encode('hex')

	def __str__(self):
		return self.to_bin()

class PreorderNameOp(NameOp):
	opcode = Opcode.PREORDER

	def __init__(self, name_hash, prev_block_hash):
		self.name_hash = name_hash
		self.prev_block_hash = prev_block_hash

	@classmethod
	def from_data(cls, name, salt, prev_block_names):
		prev_block_contents = ','.join(sorted(prev_block_names))
		name_hash = bin_hash160(name + salt)
		prev_block_hash = bin_hash160(prev_block_contents)[:-1]
		nameop = cls(name_hash, prev_block_hash)
		return nameop

	def to_bin(self):
		return self.opcode + self.name_hash + self.prev_block_hash

class ClaimNameOp(NameOp):
	opcode = Opcode.CLAIM

	def __init__(self, name, salt):
		self.name = name.lstrip(PADDING_BYTE)
		self.salt = salt

	def to_bin(self):
		return self.opcode + self.packed_name() + self.salt

class UpdateNameOp(NameOp):
	opcode = Opcode.UPDATE

	def __init__(self, name, value_hash):
		self.name = name.lstrip(PADDING_BYTE)
		self.value_hash = value_hash

	@classmethod
	def from_data(cls, name, update):
		return cls(name, bin_hash160(update))

	def to_bin(self):
		return self.opcode + self.packed_name() + self.value_hash

class TransferNameOp(NameOp):
	opcode = Opcode.TRANSFER

	def __init__(self, name):
		self.name = name.lstrip(PADDING_BYTE)

	def to_bin(self):
		return self.opcode + self.packed_name()

