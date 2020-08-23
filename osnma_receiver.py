import os
import csv
import pandas as pd
import bitstring as bs
import osnma_core as osnma

class OSNMA_receiver:

    hkroot_start = 138
    hkroot_length = 8
    mack_start = 146
    mack_length = 32
    mack_subframe_len = 480

    def __init__(self, gnss=0, svid=1, msg_path=None, pubk_path=None):
        self.msg_path = msg_path
        self.gnss = gnss
        self.svid = svid
        self.pubk_path = pubk_path
        self.nav_msg_list = None
        self.verified_kroot = False

        if self.msg_path:
            self.nav_msg_list = self.__load_scenario_navmsg()

        self.osnma = osnma.OSNMACore(svid)

    def load_new_scenario(self, path):
        """Change the scenario path and loads it.
        """
        self.msg_path = path
        self.nav_msg_list = self.__load_scenario_navmsg()

    def __load_scenario_navmsg(self, gnss=None, svid=None):
        """Loads the scenario csv saved in self.path. Filters the entries by
        those with the same gnss and svid as the ones saved.

        :param gnss GNSS system: 0 for Galileo, 1 for GPS
        :type gnss int

        :param svid SVID of the satellite chosen
        :type svid int

        """
        
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
    
    def print_tesla_chain(self):
        """Save the osnma_core __key_table in a csv file for further
        consultance.
        """

        csv_file = 'KeyChain.csv'
        csv_columns = ['Index', 'WN', 'TOW', 'Key']

        try:
            with open(csv_file, 'w') as csv_descriptor:
                csv_writer = csv.DictWriter(csv_descriptor, fieldnames=csv_columns)
                csv_writer.writeheader()
                
                for key in sorted(self.osnma.get_key_table()):
                    key_entry = self.osnma.get_key_table()[key]
                    csv_writer.writerow(key_entry.get_as_dict())
        except IOError:
            raise

    def proceed_kroot_verification(self):
        """Calls the KROOT verification method from osnma_core with the
        self.pubk_path and handles the result.

        """

        self.verified_kroot = self.osnma.kroot_verification(self.pubk_path)

        if self.verified_kroot:
            print('\n\t\033[1m\033[30m\033[42m Signature verified!\033[m\n')
        else:
            print('\n\t\033[31m Bad Signature \033[m\n')

    def tesla_key_verification(self, mack_subframe, subframe_WN, subframe_TOW):
        """Extract the keys from the subframe and computes the correspondant hashes 
        until it reach the KROOT and compares it with the stored value in 
        osnma.get_data('KROOT'). Decide the number and position of keys from the 
        fields 'NMACK' and 'KS'.
        
        :param mack_subframe Subframe that contain MACs and keys.
        :type mack_subframe BitArray()

        :param subframe_WN Week Number of the subframe
        :type subframe_WN BitArray()

        :param subframe_TOW Time of Week (s) of the subframe
        :type subframe_TOW BitArray()

        """

        mack_blocks_len = self.osnma.get_meaning('NMACK')
        num_mack_blocks = self.osnma.get_data('NMACK', format='uint')

        if mack_blocks_len == 'rsvd':
            print('Not using mack')
        else:
            key_size = self.osnma.get_meaning('KS')

            bit_count = 0
            for block_index in range(num_mack_blocks):
                block = mack_subframe[bit_count:bit_count+mack_blocks_len]
                bit_count += mack_blocks_len
                macs = block[:-key_size]
                tesla_key = block[-key_size:]

                verificada, key_index = self.osnma.tesla_key_verification(tesla_key, subframe_WN, 
                                                                subframe_TOW, block_index)

                if verificada:
                    print('\033[32m Verified Key '+ str(key_index) +': \033[m' + tesla_key.hex)
                else:
                    print('\033[31m Not verified Key ' + str(key_index) +'\033[m' + tesla_key.hex)

    def mack_subframe_handle(self, waiting_subframes):
        """Process the subframes stored in waiting_subframes and then the current one.
        
        :param waiting_subframes Subframes stored as a dictionary with keys WN, TOW and MACK. Values as BitArray()
        :type waiting_subframes list

        """

        if waiting_subframes:
            print('\tPendent subframes: ')
            for subframe in waiting_subframes:
                self.tesla_key_verification(subframe['MACK'], subframe['WN'], subframe['TOW'])
            print('\tEnd of pendent subframes')

        mack_subframe = self.mack_current_subframe
        self.tesla_key_verification(mack_subframe, self.subframe_WN, self.subframe_TOW)

    def process_subframe_page(self, msg):
        """This method is called for every word read and process common variables to
        indicate the current state of the receiver such as if its a new subframe, the
        WN and TOW associate with the current subframe, if its a new DSM block, etc.
        
        :param osnma_hkroot Data to be handled as bits
        :type osnma_hkroot bs.BitArray()

        """

        if self.is_new_subframe:

            # Subframe control variables
            self.subframe_page = 1
            self.is_new_subframe = False

            # Set subframe WN and TOW correcting page offset up to 30s
            self.subframe_WN = bs.BitArray(uint=msg['WN'], length=self.osnma.get_size('GST_WN'))
            self.subframe_TOW = bs.BitArray(uint=(msg['TOW'] - msg['TOW']%30), length=self.osnma.get_size('GST_TOW'))
            
            # MACK variables
            self.mack_current_subframe = bs.BitArray()

            if (self.is_start_DSM or self.is_different_DSM):
                print('\nNew Subframe:')
                print('\tWN: ' + str(self.subframe_WN.uint))
                print('\tTOW: ' + str(self.subframe_TOW.uint))

            if self.is_start_DSM:
                self.is_start_DSM = False
                self.dsm_section_pos = 0
                self.dsm_inside_field = False
                print('\nStart DSM Message')


        else:
            self.subframe_page += 1
            if self.subframe_page >= 15:
                self.is_new_subframe = True

    def process_nma_h(self, osnma_hkroot):
        """Extract the NMA Header info from data bloc passed as parameter
        
        :param osnma_hkroot Data to be handled as bits
        :type osnma_hkroot bs.BitArray()

        """
        # Process the read NMA Header
        self.osnma.load('NMA_H', osnma_hkroot)
        bit_count = 0
        for field in self.osnma.OSNMA_sections['NMA_H']:
            n_field = osnma_hkroot[bit_count:bit_count + self.osnma.get_size(field)]
            bit_count += self.osnma.get_size(field)

            if n_field != self.osnma.get_data(field):
                self.osnma.load(field, n_field)
                self.print_read(field)
    
    def process_dsm_h(self, osnma_hkroot):
        """Extract the DSM Header info from data bloc passed as parameter
        
        :param osnma_hkroot Data to be handled as bits
        :type osnma_hkroot bs.BitArray()

        """
        # Process the read DSM Header
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
                self.is_start_DSM = True

        if prev_dsm_id != self.osnma.get_data('DSM_ID'):
            self.is_different_DSM = True
        elif self.osnma.get_meaning('BID') == 1:
            self.is_different_DSM = False
            print('Same DMS message as before\n')
        
        if self.is_different_DSM:
            for field in print_queue:
                self.print_read(field)

    def process_dsm_kroot(self, osnma_hkroot):
        """Extract the DSM KRoot info. Each time called continues in the
        last field of the message  processed in the last word.
        
        :param osnma_hkroot Data to be handled as bits
        :type osnma_hkroot bs.BitArray()

        """
        bit_count = 0
        next_page = False
        
        for field in self.osnma.OSNMA_sections['DMS_KROOT'][self.dsm_section_pos:]:
            # Load fields
            if not self.dsm_inside_field:
                if (bit_count + self.osnma.get_size(field)) <= self.hkroot_length:
                    # It fits
                    n_field = osnma_hkroot[bit_count:bit_count + self.osnma.get_size(field)]
                    bit_count += self.osnma.get_size(field)
                    self.dsm_section_pos += 1
                    self.osnma.load(field, n_field)

                    if bit_count == self.hkroot_length:
                        next_page = True

                    self.print_read(field)

                else:
                    # Start of new field that occupies more than this page
                    self.dsm_partial_fiel = osnma_hkroot[bit_count:]
                    self.dsm_inside_field = True
                    self.dsm_left_field_length = self.hkroot_length - bit_count
                    next_page = True

                    self.print_reading(field, self.dsm_left_field_length)

            else:
                if (self.osnma.get_size(field) - self.dsm_left_field_length) > self.hkroot_length:
                    # Middle of field and still not finished in this page
                    self.dsm_partial_fiel.append(osnma_hkroot)
                    self.dsm_left_field_length += self.hkroot_length
                    next_page = True

                    self.print_reading(field, self.dsm_left_field_length)

                else:
                    # End assembling the field
                    self.dsm_inside_field = False
                    self.dsm_partial_fiel.append(osnma_hkroot[:self.osnma.get_size(field)-self.dsm_left_field_length])
                    self.osnma.load(field, self.dsm_partial_fiel)

                    bit_count += (self.osnma.get_size(field)-self.dsm_left_field_length)
                    self.dsm_section_pos += 1

                    if bit_count == self.hkroot_length:
                        next_page = True               

                    self.print_read(field)

            if next_page:
                # All bits from current page read
                break

    def start(self, max_iter):
        """Starts the receiver simulation.
        """

        if self.nav_msg_list is None:
            raise TypeError('There are no messages loaded.')

        self.is_new_subframe = True
        self.is_start_DSM = True
        self.is_different_DSM = None

        mack_waiting_subframes = []
        
        # Iterate on the arriving messages
        for index, msg in self.nav_msg_list.iterrows():
            
            osnma_hkroot = bs.BitArray(hex=msg["NavMessage"])[self.hkroot_start:self.hkroot_start+self.hkroot_length]
            osnma_mack = bs.BitArray(hex=msg["NavMessage"])[self.mack_start:self.mack_start+self.mack_length]

            # Wait until transmission starts
            if (osnma_hkroot.uint + osnma_mack.uint) != 0:
                
                # Subframe page handling
                self.process_subframe_page(msg)

                # HKROOT related handling
                if self.subframe_page == 1: 
                    # NMA Header
                    self.process_nma_h(osnma_hkroot)
                elif self.subframe_page == 2:
                    # DMS Header
                    self.process_dsm_h(osnma_hkroot)
                elif self.is_different_DSM:
                    if self.osnma.get_meaning('DSM_ID') == 'DMS-KROOT ID':
                        # DMS KROOT block
                        self.process_dsm_kroot(osnma_hkroot)
                    else:
                        # DMS PubK block
                        pass
                
                # MACK related handling
                self.mack_current_subframe.append(osnma_mack)

                # Actions

                # KROOT verification
                if self.is_new_subframe and self.is_start_DSM and self.is_different_DSM:
                    self.proceed_kroot_verification()

                # Add subframes to the pending list
                if self.is_new_subframe and not self.verified_kroot:
                    mack_waiting_subframes.append({'WN': self.subframe_WN.copy(), 
                                                    'TOW': self.subframe_TOW.copy(),
                                                    'MACK': self.mack_current_subframe.copy()})

                # Verify TESLA key and MAC fields
                if self.is_new_subframe and self.verified_kroot:
                    self.mack_subframe_handle(mack_waiting_subframes)
                    mack_waiting_subframes = []
                    
            if index >= max_iter:
                # Arbitrary stop
                break

            else:
                pass
        
        self.print_tesla_chain()

if __name__ == "__main__":
    print('Running wrong file!')