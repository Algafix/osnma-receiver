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


    def load(self, field_name, data):
        try:
            # Try to create a BitArray object with the data
            if not isinstance(data, bs.BitArray):
                data = bs.BitArray(data)
            
            current_field = self.OSNMA_data[field_name]
            current_field.data = data

            # Secondary actions related to certain fields
            if(current_field.name == 'KS'):
                self.OSNMA_data['KROOT'].size = current_field.meaning(current_field.data.uint)
        except:
            raise
    

    def get_size(self, field_name):
        try:
            return self.OSNMA_data[field_name].size
        except KeyError:
            raise KeyError('Key '+str(field_name+' does not exist.'))


    def load_batch(self, data_dict):
        if not isinstance(data_dict, dict):
            raise TypeError('Expecting a dict class, not '+str(type(data_dict)))

        for key in data_dict.keys():
            self.load(key, data_dict[key])


    def kroot_verification(self, pub_key, hash=None):
        # Create the kroot signature message
        message = bs.BitArray()
        for field in self.OSNMA_crypto['kroot_sm']:
            message.append(self.OSNMA_data[field].data)
        
        # Load the correspondand key and hash function

        if hash == None:
            hashname = self.OSNMA_data['HF'].meaning(self.OSNMA_data['HF'].data.uint)
            if hashname == 'SHA256':
                hash = hashlib.sha256
            elif hashname == 'SHA3_224':
                hash = hashlib.sha3_224
            elif hashname == 'SHA3_256':
                hash = hashlib.sha3_256
            else:
                raise TypeError("Hash not supported")

        with open(pub_key) as f:
            try:
                vk = ecdsa.VerifyingKey.from_pem(f.read(), hashfunc=hash)
            except IOError as e:
                print("I/O error({0}): {1}".format(e.errno, e.strerror))

        # Proceed with the verification
        verification_result = None
        try:
            verification_result = vk.verify(self.OSNMA_data['DS'].data.bytes, message.bytes)
        except ecdsa.BadSignatureError as e:
            verification_result = False
        finally:
            return verification_result



if __name__ == "__main__":
    print("You're running the wrong file")








