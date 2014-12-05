import re

def count_non_alphabetics(s):
    return len(re.findall('[^a-z]', s))

def is_alphabetic(s):
    return count_non_alphabetics(s) == 0

def calculate_name_price(name):
    SATOSHIS_PER_BTC = 10**8
    PRICE_FOR_1LETTER_NAMES = 10
    PRICE_DROP_PER_LETTER = 10
    PRICE_DROP_FOR_NON_ALPHABETIC = 10
    ALPHABETIC_PRICE_FLOOR = 10**4

    # establish the base price
    price = PRICE_FOR_1LETTER_NAMES*SATOSHIS_PER_BTC
    # adjust the price by a factor X for every character beyond the first
    price /= PRICE_DROP_PER_LETTER**(len(name)-1)

    if not is_alphabetic(name):
        # for non-alphabetic names, execute another price reduction
        price /= PRICE_DROP_FOR_NON_ALPHABETIC
    else:
        # for alphabetic names, enforce a price floor
        if price < ALPHABETIC_PRICE_FLOOR:
            price = ALPHABETIC_PRICE_FLOOR

    return price

def is_mining_fee_sufficient(name, mining_fee):
    name_price = calculate_name_price(name)
    return (mining_fee >= name_price)
