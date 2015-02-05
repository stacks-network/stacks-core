
def get_nulldata(tx):
    if not ('vout' in tx):
        return None
    outputs = tx['vout']
    # go through all the outputs
    for output in outputs:
        # make sure the output is valid
        if not ('scriptPubKey' in output):
            continue
        # grab the script pubkey
        script_pubkey = output['scriptPubKey']
        # get the script parts and script type
        script_parts = str(script_pubkey.get('asm')).split(' ')
        script_type = str(script_pubkey.get('type'))
        # if we're looking at a nulldata tx, get the nulldata
        if script_type == 'nulldata' and len(script_parts) == 2:
            return script_parts[1]
    return None


def has_nulldata(tx):
    return (get_nulldata(tx) is not None)
