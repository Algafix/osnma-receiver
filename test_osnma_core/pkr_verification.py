import sys
import os.path

sys.path.insert(0, os.path.dirname(sys.path[0]))

import hashlib
import bitstring as bs
from auxiliar_data.test_data import PKRVECTOR,MERKLEROOT
import osnma_core

# Instanciate local structures

pkr_message = bs.BitArray(PKRVECTOR)
merkle_root = bs.BitArray(MERKLEROOT)

osnma = osnma_core.OSNMACore()
osnma.set_merkle_root(merkle_root)

# Disfragment the raw message

auth = osnma.dms_pkr_process(pkr_message)

print('\n==========================================')

if auth:
    print('\n\t\033[1m\033[30m\033[42m PubK verified! \033[m')
else:
    print('\n\t\033[31m Bad PubK \033[m')

print('\n==========================================')
