import json, os, sys, json, argparse, traceback
from binascii import hexlify, unhexlify
from nameop import *

def interpret_nameop(db, sender, op_return_data, outputs):
	names = db.names
	block_names = db.block_names
	block_preorders = db.block_preorders

	nameop = parse_nameop(op_return_data)
	if nameop.opcode == Opcode.PREORDER:
		# record the value for claims
		block_preorders['current'].append(nameop.to_hex())
	elif nameop.opcode == Opcode.CLAIM:
		# check whether a matching preorder was executed in the previous block
		preorder = PreorderNameOp.from_data(nameop.name, nameop.salt, block_names['prev_prev'])
		if preorder.to_hex() in block_preorders['prev']:
			# record the name in the name table
			names[nameop.name] = { 'value_hash': '', 'owner': sender }
			block_names['current'].append(nameop.name)
	elif nameop.opcode == Opcode.UPDATE:
		# check whether the name's owner or admin matches the current tx sender
		if nameop.name in names and (names[nameop.name].get('owner') == sender
			or names[nameop.name].get('admin') == sender):
			# record the value update
			names[nameop.name]['value_hash'] = hexlify(nameop.value_hash)
	elif nameop.opcode == Opcode.TRANSFER:
		# check whether the name's owner matches the current tx sender
		if nameop.name in names and names[nameop.name].get('owner') == sender:
			# record transfer of ownership and admin rights
			names[nameop.name]['owner'] = outputs[0]
			if len(outputs) > 1:
				names[nameop.name]['admin'] = outputs[1]

class DB():
	names = {}
	block_preorders = {'prev': [], 'current': []}
	block_names = {'prev_prev': [], 'prev': [], 'current': [] }

def get_names(blockchain):
	db = DB()

	# iterate through each block in the blockchain
	for block in blockchain:
		# iterate through all the transactions in the current block
		transactions = block['transactions']
		for transaction in transactions:
			# check if there is op_return data present in the transaction
			op_return_data = transaction.get('op_return', None)
			if op_return_data:
				# inspect the op_return data and interpret it
				interpret_nameop(db, transaction['sender'], op_return_data, transaction['outputs'])
		
		# shift all the block names back by one block
		db.block_names['prev_prev'] = db.block_names['prev']
		db.block_names['prev'] = db.block_names['current']
		db.block_names['current'] = []
		
		# shift all the preorders back by one block
		db.block_preorders['prev'] = db.block_preorders['current']
		db.block_preorders['current'] = []

	return db.names

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Get the registered names for a given set of blockchain data.')
	parser.add_argument('filename', metavar='F',
                   		help='the name of the blockchain data file')
	args = parser.parse_args()

	with open(args.filename, 'r') as f:
		blockchain_data = json.loads(f.read())

	names = get_names(blockchain_data)
	print json.dumps(names, indent=4)




