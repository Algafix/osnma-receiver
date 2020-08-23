import sys
import os.path

sys.path.insert(0, os.path.dirname(sys.path[0]))

import hashlib
import osnma_core
import bitstring as bs
from auxiliar_data.test_data import TESTVECTOR


# Initialization of common values for the chain verification
osnma = osnma_core.OSNMACore(svid=2)

key = bs.BitArray(hex='22B30FBEE8C6C4A43480AF28A67D4A65')
key_wn = bs.BitArray(uint=947, length=osnma.OSNMA_data['GST_WN'].size)
key_tow = bs.BitArray(uint=(432000), length=osnma.OSNMA_data['GST_TOW'].size)
position = 0

ks = bs.BitArray('0b0100')
hf = bs.BitArray('0b00')
nmack = bs.BitArray('0b10')
alpha = bs.BitArray(hex='F1CA3856A975')

kroot = bs.BitArray(hex='EE6772D9AB8396866DC57EADA1D29637')
kroot_wn = bs.BitArray(uint=947, length=osnma.OSNMA_data['KROOT_WN'].size)
kroot_towh = bs.BitArray(uint=(432000//3600), length=osnma.OSNMA_data['KROOT_TOWH'].size)


osnma.load_batch({'KS':ks, 'HF':hf, 'NMACK':nmack, 'alpha':alpha,
                'KROOT_WN':kroot_wn, 'KROOT_TOWH':kroot_towh, 'KROOT':kroot})

verificada = osnma.tesla_key_verification(key, key_wn, key_tow, position)

if verificada:
    print('\n\t\033[1m\033[30m\033[42m Chain verified! \033[m\n')
else:
    print('\n\t\033[31m Keys are diferent! \033[m\n')
