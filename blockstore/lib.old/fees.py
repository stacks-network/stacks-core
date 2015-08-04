import re
import math 

from .config import DEFAULT_OP_RETURN_FEE, SATOSHIS_PER_BTC


def is_alphabetic(s):
    return len(re.findall('[^a-z]', s)) == 0


def has_numerics(s):
    return len(re.findall('[0-9]', s)) > 0


def has_underscores_or_dashes(s):
    return len(re.findall('[-_]', s)) > 0


def calculate_basic_name_tx_fee():
    return DEFAULT_OP_RETURN_FEE

def calculate_name_price(name, namespace_base_price, namespace_decay):
    
    # establish the base price (in satoshis)
    price = float(namespace_base_price)
    
    # adjust the price by a factor X for every character beyond the first
    price = ceil( price / (namespace_decay**(len(name)-1)) )
    
    # price cannot be lower than 1 satoshi
    if price < 1:
       price = 1
    
    return price
 

def is_mining_fee_sufficient(name, mining_fee, namespace_base_price, namespace_decay):
    name_price = 0
    # TODO: use namespace pricing
    # name_price = calculate_name_price(name, namespace_base_price, namespace_decay)
    return (mining_fee >= name_price)
