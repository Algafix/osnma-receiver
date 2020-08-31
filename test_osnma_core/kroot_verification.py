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
ds_size = KROOTVECTOR['DS_len']
nma_h = bs.BitArray(KROOTVECTOR['NMA_H'])

verificada = osnma.dms_kroot_process(kroot_raw, pubk, nma_h, ds_size)

if verificada:
    print('\n\t\033[1m\033[30m\033[42m Signature verified!\033[m\n')
else:
    print('\n\t\033[31m Bad Signature \033[m\n')


