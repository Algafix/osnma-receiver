import os
import pandas as pd
import bitstring as bs
import osnma_core as osnma

class OSNMA_receiver:

    hkroot_start = 138
    hkroot_length = 8
    mack_start = 146
    mack_length = 32

    def __init__(self, gnss=0, svid=1, msg_path=None, pubk_path=None):
        self.msg_path = msg_path
        self.gnss = gnss
        self.svid = svid
        self.pubk_path = pubk_path
        self.nav_msg_list = None


        if self.msg_path:
            self.nav_msg_list = self.__load_scenario_navmsg()

        self.osnma = osnma.OSNMACore(svid)

    def load_new_scenario(self, path):
        self.msg_path = path
        self.nav_msg_list = self.__load_scenario_navmsg()

    def __load_scenario_navmsg(self, gnss=None, svid=None):
        
        if gnss is None:
            gnss = self.gnss
        if svid is None:
            svid = self.svid

        name, ext = self.msg_path.split('.')
        reduced_path = name + '_' + str(gnss) + str(svid) + '.' + ext

        if os.path.exists(reduced_path):
            nav_msg = pd.read_csv(reduced_path)
        else:
            nav_msg_header = ['Date', 'Time', 'GNSS', 'SVID', 'WN', 'TOW', 'NavMessage']
            nav_msg = pd.read_csv(self.msg_path, header=None, names=nav_msg_header, index_col='Date')

            gnss_is_galileo = nav_msg.GNSS == 0
            svid_is_one = nav_msg.SVID == 1
            all_filters = gnss_is_galileo & svid_is_one
            nav_msg = nav_msg[all_filters]

            nav_msg.to_csv(reduced_path)
            nav_msg = pd.read_csv(reduced_path)

        return nav_msg
    
    def print_read(self, field):
        if self.osnma.get_repr(field) == None:
            print('Read ' + self.osnma.get_description(field) + ': ' + 
            str(self.osnma.get_meaning(field)) + 
            ' (0b' + self.osnma.get_data(field).bin + ')')
        else:
            print('Read ' + self.osnma.get_description(field) + ': ' + 
            str(self.osnma.get_meaning(field)))

    def print_reading(self, field, bits):
        print('Reading ' + str(self.osnma.get_description(field)) + 
                ' (' + str(bits) + '/' + str(self.osnma.get_size(field)) + ')')

    def start(self, max_iter):

        if self.nav_msg_list is None:
            raise TypeError('There are no messages loaded.')

        is_new_subframe = True
        is_start_DSM = True
        
        # Iterate on the arriving messages
        for index, msg in self.nav_msg_list.iterrows():
            
            osnma_hkroot = bs.BitArray(hex=msg["NavMessage"])[self.hkroot_start:self.hkroot_start+self.hkroot_length]
            osnma_mack = bs.BitArray(hex=msg["NavMessage"])[self.mack_start:self.mack_start+self.mack_length]

            # Wait until transmission starts
            if (osnma_hkroot.uint + osnma_mack.uint) != 0:
                
                # General handeling
                if is_new_subframe:
                    
                    # Subframe local variables
                    subframe_page = 1
                    is_new_subframe = False

                    # Set subframe WN and TOW correcting page offset until 30s
                    subframe_WN = bs.BitArray(uint=msg['WN'], length=self.osnma.get_size('GST_WN'))
                    subframe_TOW = bs.BitArray(uint=(msg['TOW'] - msg['TOW']%30), length=self.osnma.get_size('GST_TOW'))
                    
                    if(is_start_DSM or is_different_DSM):
                        print('\nNew Subframe:')
                        print('\tWN: ' + str(subframe_WN.uint))
                        print('\tTOW: ' + str(subframe_TOW.uint))

                    if is_start_DSM:
                        is_start_DSM = False
                        section_pos = 0
                        middle_field = False
                        print('\nStart DSM Message')

                else:
                    subframe_page += 1
                    if subframe_page >= 15:
                        is_new_subframe = True

                # Message related handeling
                if subframe_page == 1:
                    # NMA Header

                    self.osnma.load('NMA_H', osnma_hkroot)
                    bit_count = 0
                    for field in self.osnma.OSNMA_sections['NMA_H']:
                        n_field = osnma_hkroot[bit_count:bit_count + self.osnma.get_size(field)]
                        bit_count += self.osnma.get_size(field)

                        if n_field != self.osnma.get_data(field):
                            self.osnma.load(field, n_field)
                            self.print_read(field)

                elif subframe_page == 2:
                    # DMS Header

                    bit_count = 0
                    prev_dsm_id = self.osnma.get_data('DSM_ID')
                    print_queue = []

                    for field in self.osnma.OSNMA_sections['DSM_H']:
                        n_field = osnma_hkroot[bit_count:bit_count + self.osnma.get_size(field)]
                        bit_count += self.osnma.get_size(field)
                        if n_field != self.osnma.get_data(field):
                            self.osnma.load(field, n_field)
                            print_queue.append(field)

                    if self.osnma.get_data('NB') != None:
                        if self.osnma.get_meaning('BID') >= self.osnma.get_meaning('NB'):
                            is_start_DSM = True

                    if prev_dsm_id != self.osnma.get_data('DSM_ID'):
                        is_different_DSM = True
                    elif self.osnma.get_meaning('BID') == 1:
                        is_different_DSM = False
                        print('Same DMS message as before\n')
                    
                    if is_different_DSM:
                        for field in print_queue:
                            self.print_read(field)

                else:
                    if self.osnma.get_data('DSM_ID', format='uint') < 12 and is_different_DSM:
                        # DMS-KROOT block
                        bit_count = 0
                        next_page = False
                        
                        for field in self.osnma.OSNMA_sections['DMS_KROOT'][section_pos:]:
                            # Load fields
                            if not middle_field:
                                if (bit_count + self.osnma.get_size(field)) <= self.hkroot_length:
                                    # It fits
                                    n_field = osnma_hkroot[bit_count:bit_count + self.osnma.get_size(field)]
                                    bit_count += self.osnma.get_size(field)
                                    section_pos += 1
                                    self.osnma.load(field, n_field)

                                    if bit_count == self.hkroot_length:
                                        next_page = True

                                    self.print_read(field)

                                else:
                                    # Start of new field that occupies more than this page
                                    part_field = osnma_hkroot[bit_count:]
                                    middle_field = True
                                    current_size = self.hkroot_length - bit_count
                                    next_page = True

                                    self.print_reading(field, current_size)

                            else:
                                if (self.osnma.get_size(field) - current_size) > self.hkroot_length:
                                    # Middle of field and still not finished in this page
                                    part_field.append(osnma_hkroot)
                                    current_size += self.hkroot_length
                                    next_page = True

                                    self.print_reading(field, current_size)

                                else:
                                    # End assembling the field
                                    middle_field = False
                                    part_field.append(osnma_hkroot[:self.osnma.get_size(field)-current_size])
                                    self.osnma.load(field, part_field)

                                    bit_count += (self.osnma.get_size(field)-current_size)
                                    section_pos += 1

                                    if bit_count == self.hkroot_length:
                                        next_page = True               

                                    self.print_read(field)

                            if next_page:
                                # All bits from current page read
                                break
            
            
                if is_new_subframe and is_start_DSM and is_different_DSM:
                    if self.osnma.kroot_verification(self.pubk_path):
                        print('\n\t\033[1m\033[30m\033[42m Signature verified!\033[m\n')
                    else:
                        print('\n\t\033[31m Bad Signature \033[m\n')

            if index >= max_iter:
                break

            else:
                pass

if __name__ == "__main__":
    print('Running wrong file!')