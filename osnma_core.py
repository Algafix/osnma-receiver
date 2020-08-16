import bitstring as bs
import sys
import ecdsa
import hashlib
import auxiliar_data.osnma_fields as osnma_fields
import auxiliar_data.osnma_structures as osnma_structures

class OSNMACore:

    def __init__(self):
        self.OSNMA_data = osnma_fields.OSNMA_fields
        self.OSNMA_sections = osnma_structures.section_structures
        self.OSNMA_crypto = osnma_structures.cryptographic_structures

    def kroot_verification(self, pub_key='auxiliar_data/PubK.pem'):

        kroot_sm = bs.BitArray()

        for field in self.OSNMA_crypto['kroot_sm']:
            kroot_sm.append(self.OSNMA_data[field].data)
            
        with open(pub_key) as f:
            vk = ecdsa.VerifyingKey.from_pem(f.read(), hashfunc=hashlib.sha256)
        try:
            vk.verify(self.OSNMA_data['DS'].data.bytes, kroot_sm.bytes)
            print('\n==========================================')
            print('\n\t\033[1m\033[30m\033[42m Signature verified!\033[m')
            print('\n==========================================')
        except ecdsa.BadSignatureError as e:
            print('\n==========================================')
            print('\t\033[31m Bad Signature \033[m')
            print('\n==========================================')
        except FileNotFoundError as e:
            print('\t FILE NOT FOUND')




if __name__ == "__main__":
    print("You're running the wrong file")








