import bitstring as bs
import math
import sys
import hmac
import ecdsa
import hashlib
import auxiliar_data.osnma_fields as osnma_fields
import auxiliar_data.osnma_structures as osnma_structures


class OSNMACore:

    __hash_table = {'SHA256': hashlib.sha256, 'SHA3_224': hashlib.sha3_224, 'SHA3_256': hashlib.sha256}

    def __init__(self, svid=1):
        self.OSNMA_data = osnma_fields.OSNMA_fields
        self.OSNMA_sections = osnma_structures.section_structures
        self.OSNMA_crypto = osnma_structures.cryptographic_structures
        self.pubk_lengths = osnma_structures.pubk_lengths
        self.svid = svid
        self.load('PRN',bs.BitArray(uint=svid, length=self.get_size('PRN')))
        self.__NS = 36
        self.__HF = None
        self.__MF = None
        self.__key_table = {}

    def __macs_per_mackblock(self, nmack=None, ks=None, ms=None):
        # Load parameters
        if not nmack:
            nmack = self.OSNMA_data['NMACK'].get_data_uint()
        if not ks:
            ks = self.OSNMA_data['KS'].get_meaning()
        if not ms:
            ms = self.OSNMA_data['MS'].get_meaning()
        
        return math.floor(((480/nmack) - ks)//(ms + 16))

    def get_key_index(self, gst, position, svid=None, ns=None, nmack=None, gst_0=None):
        if not svid:
            svid = self.svid
        if not ns:
            ns = self.__NS
        if not nmack:
            nmack = self.OSNMA_data['NMACK'].get_data_uint()
        if not gst_0:
            gst_0 = self.__get_gst0()

        past_keys = ((gst.uint - gst_0.uint)//30) * ns * nmack
        key_index = past_keys + ns * position + svid

        return key_index 

    def __get_gst0(self):

        gst_0 = bs.BitArray(self.OSNMA_data['KROOT_WN'].get_data())
        tow_s = self.OSNMA_data['KROOT_TOWH'].get_data_uint() * 3600
        gst_0.append(bs.BitArray(uint=tow_s, length=20))

        return gst_0

    def __gst_subfragment(self, m, ns=None, gst_0=None, nmack=None):

        if m == 0:
            gst_subfragment = self.__key_table[0].wn + self.__key_table[0].tow
        else:
            # Load parameters
            if not ns:
                ns = self.__NS
            if not nmack:
                nmack = self.OSNMA_data['NMACK'].get_data_uint()
            if not gst_0:
                gst_0 = self.__get_gst0().uint
            
            gst_subfragment = gst_0 + 30 * math.floor((m-1)//(ns * nmack))
            gst_subfragment = bs.BitArray(uint=gst_subfragment, length=32)

        return gst_subfragment

    def get_data(self, field_name, format=None):
        field = self.OSNMA_data[field_name]
        if field.get_data() == None:
            return None
        elif format == None:
            return field.get_data()
        elif format == 'uint':
            return field.get_data_uint()
        elif format == 'bytes':
            return field.get_data_bytes()
        else:
            raise TypeError('Format not accepted (None, uint, bytes)')
    
    def get_key_table(self):
        return self.__key_table

    def get_meaning(self, field_name):
        return self.OSNMA_data[field_name].get_meaning()

    def get_description(self, field_name):
        return self.OSNMA_data[field_name].get_description()

    def get_repr(self, field_name):
        return self.OSNMA_data[field_name].get_repr()

    def get_field(self, field_name):
        return self.OSNMA_data[field_name]

    def load(self, field_name, data):
        try:
            # Try to create a BitArray object with the data
            if not isinstance(data, bs.BitArray):
                data = bs.BitArray(data)
            
            current_field = self.OSNMA_data[field_name]
            current_field.set_data(data)

            # Secondary actions related to certain fields
            if current_field.name == 'KS':
                self.OSNMA_data['KROOT'].size = current_field.get_meaning()
            elif current_field.name == 'HF':
                self.__HF = current_field.get_meaning()
            elif current_field.name == 'MF':
                self.__MF = current_field.get_meaning()
            elif current_field.name == 'KROOT':
                entry_wn = self.OSNMA_data['KROOT_WN'].get_data()
                entry_tow = self.OSNMA_data['KROOT_TOWH'].get_data_uint()*3600 - 30
                entry_tow = bs.BitArray(uint=entry_tow, length=20)
                self.__key_table[0] = osnma_structures.KeyEntry(0, entry_wn, entry_tow, data)
            elif current_field.name == 'NPKT':
                ds_alg = current_field.get_meaning()[0]
                ds_alg_info = osnma_structures.pubk_lengths[ds_alg]
                self.OSNMA_data['DS'].size = ds_alg_info['signature']
                self.OSNMA_data['NPK'].size = ds_alg_info['npk']
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

    def kroot_verification(self, pub_key, hash_name=None):
        # Create the kroot signature message
        message = bs.BitArray()
        for field in self.OSNMA_crypto['kroot_sm']:
            message.append(self.OSNMA_data[field].get_data())
        
        # Load the correspondand hash function
        if hash_name == None:
            hash_name = self.__HF
        
        try:
            hash = self.__hash_table[hash_name]
        except KeyError:
            raise TypeError("Hash not supported: " + hash_name)

        # Load key and create sign object
        with open(pub_key) as f:
            try:
                vk = ecdsa.VerifyingKey.from_pem(f.read(), hashfunc=hash)
            except IOError as e:
                print("I/O error({0}): {1}".format(e.errno, e.strerror))

        # Proceed with the verification
        verification_result = None
        try:
            verification_result = vk.verify(self.OSNMA_data['DS'].get_data_bytes(), message.tobytes())
        except ecdsa.BadSignatureError as e:
            verification_result = False
        finally:
            return verification_result

    def tesla_key_verification(self, key, gst_wn, gst_tow, position, svid=None, alpha=None):

        if not alpha:
            alpha = self.OSNMA_data['alpha'].get_data()
        if not svid:
            svid = self.svid

        key_size = self.OSNMA_data['KS'].get_meaning()
        gst = gst_wn + gst_tow
        key_index = self.get_key_index(gst, position, svid)
        new_keys_dict = {}

        new_keys_dict[key_index] = osnma_structures.KeyEntry(key_index, gst_wn, gst_tow, key)

        for index in reversed(range(key_index)):
            gst = self.__gst_subfragment(index)
            hash_object = hashlib.new(self.__HF)
            hash_object.update((key + gst + alpha).bytes)
            prev_key = bs.BitArray(hash_object.digest())
            key = prev_key[:key_size]

            if index not in self.__key_table.keys():
                new_keys_dict[index] = osnma_structures.KeyEntry(index, gst[:12], gst[12:], key)
            else:
                verified = (key == self.__key_table[index].key)
                break

        if verified:
            self.__key_table.update(new_keys_dict)

        return verified, key_index

    def filter_navigation_data(self, nav_data, adkd):
        """Filters nav_data depending on the adkd parameter. Return all the nav_data to
        verifiy concatenated.

        :param nav_data List with 15 BitArray objects containing full pages of the sub frame
        :type nav_data list

        :param adkd Authentication Data and Key Delay that indicates the data to authenticate
        :type int
        """
        filtered_nav_data = bs.BitArray()
        data_masks = osnma_structures.adkd_masks[adkd]

        for mask in data_masks:
            page = mask['page']
            for bit_block in mask['bits']:
                filtered_nav_data.append(nav_data[page][bit_block[0]:bit_block[1]])
        
        return filtered_nav_data

    def format_mack_data(self, raw_mack_data):
        """Returns a list of list with the mack blocks and each entry.

        :param raw_mack_data Subframe mack data with keys
        :type BitArray
        """

        mack_block_len = self.get_meaning('NMACK')
        blocks_per_mack = self.get_data('NMACK', format='uint')
        key_len = self.get_meaning('KS')
        macs_per_block = self.__macs_per_mackblock()
        mac_entry_len = self.get_meaning('MS') + 16

        mack_blocks = []
        for block_index in range(blocks_per_mack):
            mack_block = raw_mack_data[block_index*mack_block_len:(block_index+1)*mack_block_len-key_len]
            mac_entries = []
            for mac_index in range(macs_per_block):
                mac_entry = mack_block[mac_index*mac_entry_len:(mac_index+1)*mac_entry_len]
                mac_entries.append(mac_entry)
            mack_blocks.append(mac_entries)

        return mack_blocks

    def mac_seq_verification(self, mack_block, key):
        """Verify mac seq field of the first mac entry on the first mack block.
        
        :param mack_block List with mac entries as BitArray
        :type mack_block list

        :param key Key of the first mack_block.
        :type BitArray
        """

        # Construct the message to be authenticated
        mac_lt = self.get_meaning('MACLT')
        seq_list = osnma_structures.mac_lookup_table[mac_lt]['sequence']
        mac_seq = mack_block[0][-16:-4]
        authenticated_seq = self.get_data('PRN') + self.get_data('GST_WN') + self.get_data('GST_TOW')

        for index, slot in enumerate(seq_list):
            if slot == 'FLX':
                authenticated_seq.append(mack_block[index][:-16])
        
        # Choose algorithm
        if self.__MF == 'HMAC-SHA-256':
            hmac_seq = hmac.new(key=key.bytes, msg=authenticated_seq.bytes, digestmod=hashlib.sha256)
            computed_mac_seq = bs.BitArray(hmac_seq.digest())[:12]
        elif self.__MF == 'CMAC-AES':
            raise TypeError('CMAC-AES not implemented')
        else:
            raise TypeError('MAC function rsvd')

        return computed_mac_seq == mac_seq, computed_mac_seq, mac_seq

    def mac0_verification(self, mac_entry, nav_data, key):
        """Compute the mac0 verification from it's entry in the first mack block, 
        the navigation data of the subframe and it's correspondant key.

        :param mac_entry First MAC entry from the first mack block.
        :type mac_entry BitArray

        :param nav_data List with 15 BitArray objects containing full pages of the sub frame
        :type nav_data list

        :param key Key from the first mack block.
        :type key BitArray
        """
        
        filtered_nav_data = self.filter_navigation_data(nav_data, 0)

        self.load('CTR', bs.BitArray(uint=1, length=self.get_size('CTR')))
        mac_size = self.get_meaning('MS')
        tag0 = mac_entry[:mac_size]
        
        # Construct the authenticated message
        authenticated_msg = bs.BitArray()
        for field in self.OSNMA_crypto['mac0_am']:
            if field == 'P3':
                authenticated_msg = authenticated_msg.tobytes()
            elif field == 'navdata':
                authenticated_msg.append(filtered_nav_data)
            else:
                authenticated_msg.append(self.get_data(field))
        
        # Choose algorithm
        if self.__MF == 'HMAC-SHA-256':
            hmac_mac0 = hmac.new(key=key.bytes, msg=authenticated_msg, digestmod=hashlib.sha256)
            computed_tag0 = bs.BitArray(hmac_mac0.digest())[:mac_size]
        elif self.__MF == 'CMAC-AES':
            raise TypeError('CMAC-AES not implemented')
        else:
            raise TypeError('MAC function rsvd')
        
        return computed_tag0 == tag0, computed_tag0, tag0

    def mac_verification(self, mac_entry, nav_data, key, counter):
        pass

    def mack_verification(self, tesla_keys, mack_subframe, nav_data, gst_wn=None, gst_tow=None):
        
        if gst_wn and gst_tow:
            back_gst_wn = self.get_data('GST_WN')
            back_gst_tow = self.get_data('GST_TOW')
            self.load_batch({'GST_WN': gst_wn, 'GST_TOW': gst_tow})

        mack_formatted = self.format_mack_data(mack_subframe)
        mack_result_dict = {}
        for block_i, block in enumerate(mack_formatted):
            for mac_i, mac in enumerate(block):
                if block_i == 0 and mac_i == 0:
                    mack_result_dict['mac0'] = self.mac0_verification(mac, nav_data, tesla_keys[block_i])
                    mack_result_dict['seq'] = self.mac_seq_verification(block, tesla_keys[block_i])
                else:
                    self.mac_verification(mac, nav_data, tesla_keys[block_i], mac_i)

        if gst_wn and gst_tow:
            self.load_batch({'GST_WN': back_gst_wn, 'GST_TOW': back_gst_tow})

        return mack_result_dict


if __name__ == "__main__":
    print("You're running the wrong file")








