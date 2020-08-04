import math

def append_hex(a, b):
    sizeof_b = 0

    # get size of b in bits
    while((b >> sizeof_b) > 0):
        sizeof_b += 1

    # every position in hex in represented by 4 bits
    sizeof_b_hex = math.ceil(sizeof_b/4) * 4


    return (a << sizeof_b_hex) | b