import sys
import os.path

sys.path.insert(0, os.path.dirname(sys.path[0]))

from auxiliar_data.test_data import KROOTVECTOR
import bitstring as bs
import osnma_core 

osnma = osnma_core.OSNMACore()

# Instanciate local structures

pubk = 'auxiliar_data/PubK.pem'

kroot_raw = bs.BitArray(KROOTVECTOR['decoded'])

osnma.OSNMA_data['DS'].size = KROOTVECTOR['DS_len']
osnma.OSNMA_data['NMA_H'].data = bs.BitArray(KROOTVECTOR['NMA_H'])

# Disfragment the raw message

bit_counter = 0
for field in osnma.OSNMA_sections['DMS_KROOT']:
    if field == 'P1':
        osnma.load(field,kroot_raw[bit_counter:])
    else:
        osnma.load(field,kroot_raw[bit_counter:bit_counter+osnma.get_size(field)])
        bit_counter += osnma.get_size(field)

if osnma.kroot_verification(pubk):
    print('\n\t\033[1m\033[30m\033[42m Signature verified!\033[m\n')
else:
    print('\n\t\033[31m Bad Signature \033[m\n')
