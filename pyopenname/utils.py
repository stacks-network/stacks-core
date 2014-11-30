from utilitybelt import dev_urandom_entropy

from .configs import LENGTHS

def gen_name_preorder_salt():
    return dev_urandom_entropy(LENGTHS['salt'])

def is_int(i):
    if isinstance(i, (int,long)):
        return True
    elif isinstance(i, str):
        try:
            int_i = int(i)
        except:
            return False
        else:
            return True
    else:
        return False
