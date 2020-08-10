import ecdsa
import hashlib
from test_data import KROOTVECTOR
import message_sizes

signature_message = bytearray.fromhex(format(KROOTVECTOR['M'],'x'))

vk = ecdsa.VerifyingKey.from_pem(KROOTVECTOR['PubK'], hashfunc=hashlib.sha256)

print(message_sizes.NPKT.meaning(5))

try:
    vk.verify(bytearray.fromhex(format(KROOTVECTOR['DS'],'x')),signature_message)
    print('\n\t\033[1m\033[30m\033[42m Signature verified! \033[m')
except ecdsa.BadSignatureError as e:
    print('\t\033[31m Bad Signature \033[m')

