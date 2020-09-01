import sys
import os.path

sys.path.insert(0, os.path.dirname(sys.path[0]))

import hmac
import hashlib
import bitstring as bs
import auxiliar_data.data_structures as data_s
from auxiliar_data.test_data import MAC0VECTOR, NAVDATA

# Collect navdata to be verified

header_bits = 2
tail_bits = 6
type_bits = 6

pages_for_word = [
    ((21,22),120),
    ((1,2),120),
    ((23,24),122),
    ((3,4),120),
    ((25,26),67)]

nav_data = bs.BitArray()

for (pages, message_bits) in pages_for_word:
    full_word = bs.BitArray()
    for page in pages:
        full_word += bs.BitArray(NAVDATA[page-1])[header_bits:-tail_bits]

    nav_data.append(full_word[type_bits:type_bits+message_bits])

# MAC0 message construccion

mac_message = bs.BitArray()

for field in data_s.mac0_am:
    if field.name == 'navdata':
        mac_message.append(nav_data)
    else:
        mac_message.append(MAC0VECTOR[field.name])

# HMAC with sha-256 as per KROOT MF

mac0 = hmac.new(bs.BitArray(MAC0VECTOR['KEY']).bytes, msg = mac_message.bytes, digestmod=hashlib.sha256)
tag0 = bs.BitArray(mac0.digest())[:MAC0VECTOR['MS']]

print('\n==========================================')

if tag0 == bs.BitArray(MAC0VECTOR['MAC0']['TAG0']):
    print('\n\t\033[1m\033[30m\033[42m MAC0 verified! \033[m')
else:
    print('\n\t\033[31m Bad MAC0 \033[m')

print('\n==========================================')

# Sequence field verification

seq_message=bs.BitArray(MAC0VECTOR['PRN'])+bs.BitArray(MAC0VECTOR['GST_WN'])+bs.BitArray(MAC0VECTOR['GST_TOW'])+bs.BitArray('0b1111111101000000')+bs.BitArray('0b0001001010110000')

seq = hmac.new(bs.BitArray(MAC0VECTOR['KEY']).bytes, msg = seq_message.bytes, digestmod=hashlib.sha256)
mac_seq = bs.BitArray(hex=seq.hexdigest())[:MAC0VECTOR['MS']]

if mac_seq == bs.BitArray(MAC0VECTOR['MAC0']['SEQ']):
    print('\n\t\033[1m\033[30m\033[42m SEQ verified! \033[m')
else:
    print('\n\t\033[31m Bad SEQ \033[m')

print('\n==========================================')