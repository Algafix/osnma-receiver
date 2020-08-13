from test_data import KROOTVECTOR
import data_structures as data_s
from data_structures import Field, DataField
import ecdsa
import hashlib
import bitstring as bs


message = bs.BitArray()

for field in data_s.kroot_sm:
    if field == data_s.KROOT:
        message.append(bs.BitArray(uint=KROOTVECTOR[field.name],
                                    length=data_s.KS.meaning(KROOTVECTOR['KS'])))
    else:
        message.append(bs.BitArray(uint=KROOTVECTOR[field.name], length=field.size))

with open('PubK.pem') as f:
    vk = ecdsa.VerifyingKey.from_pem(f.read(), hashfunc=hashlib.sha256)

try:
    vk.verify(bytearray.fromhex(format(KROOTVECTOR['DS'],'x')),message.bytes)
    print('\n\t\033[1m\033[30m\033[42m Signature verified! \033[m')
except ecdsa.BadSignatureError as e:
    print('\t\033[31m Bad Signature \033[m')

