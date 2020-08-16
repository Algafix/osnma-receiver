from auxiliar_data.test_data import KROOTVECTOR
import auxiliar_data.data_structures as data_s
import ecdsa
import hashlib
import copy
import bitstring as bs

# Instanciate local structures

kroot_message = bs.BitArray(KROOTVECTOR['decoded'])

dms_kroot = copy.deepcopy(data_s.section_strutures['DMS_KROOT'])
kroot_pos = data_s.DMS_KROOT_POS

dms_kroot[kroot_pos.DS].size = KROOTVECTOR['DS_len']
nma_header = bs.BitArray(KROOTVECTOR['NMA_H'])

# Disfragment the raw message

bit_counter = 0
for field in dms_kroot:
    
    if field.name == 'P1':
        field.data = kroot_message[bit_counter:]
    else:
        field.data = kroot_message[bit_counter:bit_counter+field.size]
        bit_counter += field.size

        # Update size of the KROOT field
        if field.name == 'KS':
            dms_kroot[kroot_pos.KROOT].size = field.meaning(field.data.uint)

# Create the message to be signed

message = bs.BitArray()

for field in data_s.kroot_sm:
    if isinstance(field, data_s.Field) and field.name == 'NMA_H':
        message.append(nma_header)
    else:
        message.append(dms_kroot[field].data)

# Instanciate signature object with the PubK on a pem file

with open('auxiliar_data/PubK.pem') as f:
    vk = ecdsa.VerifyingKey.from_pem(f.read(), hashfunc=hashlib.sha256)

try:
    vk.verify(dms_kroot[kroot_pos.DS].data.bytes,message.bytes)
    print('\n==========================================')
    print('\n\t\033[1m\033[30m\033[42m Signature verified! \033[m')
    print('\n==========================================')
except ecdsa.BadSignatureError as e:
    print('\n==========================================')
    print('\t\033[31m Bad Signature \033[m')
    print('\n==========================================')

