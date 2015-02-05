import re

from .config import DEFAULT_OP_RETURN_FEE, PRICE_FOR_1LETTER_NAMES, \
    PRICE_DROP_PER_LETTER, PRICE_DROP_FOR_NON_ALPHABETIC, ALPHABETIC_PRICE_FLOOR


def is_alphabetic(s):
    return len(re.findall('[^a-z]', s)) == 0


def has_numerics(s):
    return len(re.findall('[0-9]', s)) > 0


def has_underscores_or_dashes(s):
    return len(re.findall('[-_]', s)) > 0


def calculate_basic_name_tx_fee():
    return DEFAULT_OP_RETURN_FEE


def calculate_name_price(name):
    # establish the base price
    price = PRICE_FOR_1LETTER_NAMES
    # adjust the price by a factor X for every character beyond the first
    price /= PRICE_DROP_PER_LETTER**(len(name)-1)

    if has_numerics(name) or has_underscores_or_dashes(name):
        # for names with numerics or special chars, reduce the price further
        price /= PRICE_DROP_FOR_NON_ALPHABETIC
    else:
        # for alphabetic names, enforce a price floor
        if price < ALPHABETIC_PRICE_FLOOR:
            price = ALPHABETIC_PRICE_FLOOR

    return price


def is_mining_fee_sufficient(name, mining_fee):
    name_price = 0
    # name_price = calculate_name_price(name)
    return (mining_fee >= name_price)
