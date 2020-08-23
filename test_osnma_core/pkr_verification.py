import sys
import os.path

sys.path.insert(0, os.path.dirname(sys.path[0]))

import copy
import hashlib
import bitstring as bs
import auxiliar_data.data_structures as data_s
from auxiliar_data.test_data import PKRVECTOR,MERKLEROOT

# Instanciate local structures

pkr_message = bs.BitArray(PKRVECTOR)
merkle_root = bs.BitArray(MERKLEROOT)

dms_pkr = copy.deepcopy(data_s.section_strutures['DMS_PKR'])
pkr_pos = data_s.DMS_PKR_POS

# Disfragment the raw message

bit_counter = 0
for field in dms_pkr:
    
    if field.name == 'P2':
        field.data = pkr_message[bit_counter:]
    else:
        field.data = pkr_message[bit_counter:bit_counter+field.size]
        bit_counter += field.size

        # Update size of the NPK field
        if field.name == 'NPKT':
            dms_pkr[pkr_pos.NPK].size = field.meaning(field.data.uint)[1]


dms_pkr[pkr_pos.ITN].data = [dms_pkr[pkr_pos.ITN].data[:256],
                    dms_pkr[pkr_pos.ITN].data[256:512],
                    dms_pkr[pkr_pos.ITN].data[512:768],
                    dms_pkr[pkr_pos.ITN].data[768:]]

m0 = dms_pkr[pkr_pos.NPKT].data + dms_pkr[pkr_pos.NPKTID].data + dms_pkr[pkr_pos.NPK].data
node = hashlib.sha256(m0.bytes).digest()

for key in dms_pkr[pkr_pos.ITN].data:
    node = bs.BitArray(hashlib.sha256((node + key).bytes).digest())


print('\n==========================================')

if node == merkle_root:
    print('\n\t\033[1m\033[30m\033[42m PubK verified! \033[m')
else:
    print('\n\t\033[31m Bad PubK \033[m')

print('\n==========================================')
