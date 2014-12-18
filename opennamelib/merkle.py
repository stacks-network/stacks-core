from .hashing import double_sha256, hex_to_bytes_reversed, \
    bytes_to_hex_reversed, hex_to_bin_hashes

def calculate_merkle_pairs(bin_hashes, hash_function=double_sha256):
    """ takes in a list of binary hashes, returns a binary hash
    """
    hashes = list(bin_hashes)
    # if there are an odd number of hashes, double up the last one
    if len(hashes) % 2 == 1:
        hashes.append(hashes[-1])
    # build the new list of hashes
    new_hashes = []
    for i in range(0, len(hashes), 2):
        new_hashes.append(hash_function(hashes[i] + hashes[i+1]))
    # return the new list of hashes
    return new_hashes

def calculate_merkle_root(hashes, hash_function=double_sha256, hex_format=True):
    """ takes in a list of binary hashes, returns a binary hash
    """
    if hex_format:
        hashes = hex_to_bin_hashes(hashes)
    # keep moving up the merkle tree, constructing one row at a time
    while len(hashes) > 1:
        hashes = calculate_merkle_pairs(hashes, hash_function)
    # get the merkle root
    merkle_root = hashes[0]
    # if the user wants the merkle root in hex format, convert it
    if hex_format:
        return bytes_to_hex_reversed(merkle_root)
    # return the binary merkle root
    return merkle_root

class MerkleTree():
    def __init__(self, hashes, hex_format=True, hash_function=double_sha256):
        if not len(hashes) > 0:
            raise ValueError("At least one hash is required.")

        self.rows = []

        # if the hashes are in hex format, first convert them to binary
        if hex_format:
            hashes = hex_to_bin_hashes(hashes)

        # build the rows of the merkle tree
        self.rows.append(hashes)
        while len(hashes) > 1:
            hashes = calculate_merkle_pairs(hashes, hash_function)
            self.rows.append(hashes)

    def get(self, row_index, column_index):
        # check to make sure there are enough rows
        if row_index + 1 > len(self.rows):
            raise ValueError("There aren't that many rows.")
        row = self.rows(row_index)
        # check to make sure there are enough items in the row
        if column_index + 1 > len(row):
            raise ValueError("There aren't that many items in that row.")
        # return the requested item
        return row[column_index]

    def root(self, hex_format=True):
        # return the merkle root
        bin_merkle_root = self.rows[-1][0]
        if hex_format:
            return bytes_to_hex_reversed(bin_merkle_root)
