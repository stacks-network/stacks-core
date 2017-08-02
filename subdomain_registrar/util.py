import blockstack_zones
import copy

SUBDOMAIN_ZF_PARTS = "parts"
SUBDOMAIN_ZF_PIECE = "zf%d"
SUBDOMAIN_SIG = "sig"
SUBDOMAIN_PUBKEY = "owner"
SUBDOMAIN_N = "seqn"

def is_subdomain_record(rec):
    txt_entry = rec['txt']
    if not isinstance(txt_entry, list):
        return False
    has_parts_entry = False
    has_pk_entry = False
    has_seqn_entry = False
    for entry in txt_entry:
        if entry.startswith(SUBDOMAIN_ZF_PARTS + "="):
            has_parts_entry = True
        if entry.startswith(SUBDOMAIN_PUBKEY + "="):
            has_pk_entry = True
        if entry.startswith(SUBDOMAIN_N + "="):
            has_seqn_entry = True
    return (has_parts_entry and has_pk_entry and has_seqn_entry)

def add_subdomains(subdomains, domain_fqa, zonefile_json, filter_function = None):
    if filter_function is None:
        filter_function = (lambda subdomain, domain: True)

    zf = copy.deepcopy(zonefile_json)
    if "txt" in zf:
        zf["txt"] = list([ x for x in zf["txt"]
                           if not is_subdomain_record(x)])

    if len(set(subdomains)) != len(subdomains):
        raise Exception("Same subdomain listed multiple times")

    subdomains_failed = []
    for ix, subdomain in enumerate(subdomains):
        # step 1: see if this resolves to an already defined subdomain
        filter_passed = filter_function(subdomain.name, domain_fqa)
        if not filter_passed:
            subdomains_failed.append(ix)
        else:
            # step 2: create the subdomain record, adding it to zf
            try:
                _extend_with_subdomain(zf, subdomain)
            except Exception as e:
                subdomains_failed.append(ix)

    zf_txt = blockstack_zones.make_zone_file(zf)
    return zf_txt, subdomains_failed

def _extend_with_subdomain(zf_json, subdomain):
    """
    subdomain := one of (Subdomain Object, packed subdomain = list<string>)
    """
    if isinstance(subdomain, list):
        txt_data = subdomain
    else:
        try:
            txt_data = subdomain.pack_subdomain()
        except:
            raise ParseError("Tried to extend zonefile with non-valid subdomain object")

    name = subdomain.name

    if "txt" not in zf_json:
        zf_json["txt"] = []

    txt_records = zf_json["txt"]

    for rec in txt_records:
        if name == rec["name"]:
            raise Exception("Name {} already exists in zonefile TXT records.".format(
                name))

    zf_json["txt"].append(subdomain.as_zonefile_entry())

class ParseError(Exception):
    pass
