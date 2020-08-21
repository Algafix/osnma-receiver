import os
import pandas as pd
import bitstring as bs
import osnma_core as osnma


default_path = 'scenarios/TV200_DsmKroot1/log/20200115_135442/NavMsg.csv'
pubk_path = 'scenarios/TV200_DsmKroot1/input/pk/pub_pem_256v1.pem'
hkroot_start = 138
hkroot_length = 8
mack_start = 146
mack_length = 32

def load_scenario_navmsg(path, gnss=0, svid=1):
    
    name, ext = path.split('.')
    reduced_path = name + '_' + str(gnss) + str(svid) + '.' + ext

    if os.path.exists(reduced_path):
        nav_msg = pd.read_csv(reduced_path)
    else:
        nav_msg_header = ['Date', 'Time', 'GNSS', 'SVID', 'WN', 'TOW', 'NavMessage']
        nav_msg = pd.read_csv(path, header=None, names=nav_msg_header, index_col='Date')

        gnss_is_galileo = nav_msg.GNSS == 0
        svid_is_one = nav_msg.SVID == 1
        all_filters = gnss_is_galileo & svid_is_one
        nav_msg = nav_msg[all_filters]

        nav_msg.to_csv(reduced_path)
        nav_msg = pd.read_csv(reduced_path)

    return nav_msg

def print_read(osnma, field):
    if osnma.get_repr(field) == None:
        print('Read ' + osnma.get_description(field) + ': ' + 
        str(osnma.get_meaning(field)) + 
        ' (0b' + osnma.get_data(field).bin + ')')
    else:
        print('Read ' + osnma.get_description(field) + ': ' + 
        str(osnma.get_meaning(field)))

def print_reading(osnma, field, bits):
    print('Reading ' + str(osnma.get_description(field)) + 
            ' (' + str(bits) + '/' + str(osnma.get_size(field)) + ')')



if __name__ == "__main__":
    
    nav_msg = load_scenario_navmsg(default_path)
    svid = 1
    NPKT = '0b0001'
    NPKID = '0b0000'
    osnma = osnma.OSNMACore(svid)
    osnma.load('NPKT', NPKT)
    osnma.load('NPKID', NPKID)


    is_new_subframe = True
    is_start_DSM = True
    
    # Iterate on the arriving messages
    for index, msg in nav_msg.iterrows():
        
        osnma_hkroot = bs.BitArray(hex=msg["NavMessage"])[hkroot_start:hkroot_start+hkroot_length]
        osnma_mack = bs.BitArray(hex=msg["NavMessage"])[mack_start:mack_start+mack_length]

        # Wait until transmission starts
        if (osnma_hkroot.uint + osnma_mack.uint) != 0:
            
            # General handeling
            if is_new_subframe:
                
                # Subframe local variables
                subframe_page = 1
                is_new_subframe = False

                # Set subframe WN and TOW correcting page offset until 30s
                subframe_WN = bs.BitArray(uint=msg['WN'], length=osnma.get_size('GST_WN'))
                subframe_TOW = bs.BitArray(uint=(msg['TOW'] - msg['TOW']%30), length=osnma.get_size('GST_TOW'))
                
                print('\nNew Subframe:')
                print('\tWN: ' + str(subframe_WN.uint))
                print('\tTOW: ' + str(subframe_TOW.uint))

                if is_start_DSM:
                    is_start_DSM = False
                    section_pos = 0
                    middle_field = False
                    print('\nStart DSM Message')

                print('\n')

            else:
                subframe_page += 1
                if subframe_page >= 15:
                    is_new_subframe = True

            # Message related handeling
            if subframe_page == 1:
                # NMA Header

                osnma.load('NMA_H', osnma_hkroot)
                bit_count = 0
                for field in osnma.OSNMA_sections['NMA_H']:
                    n_field = osnma_hkroot[bit_count:bit_count + osnma.get_size(field)]
                    bit_count += osnma.get_size(field)

                    if n_field != osnma.get_data(field):
                        osnma.load(field, n_field)
                        print_read(osnma, field)

            elif subframe_page == 2:
                # DMS Header

                bit_count = 0
                prev_dsm_id = osnma.get_data('DSM_ID')

                for field in osnma.OSNMA_sections['DSM_H']:
                    n_field = osnma_hkroot[bit_count:bit_count + osnma.get_size(field)]
                    bit_count += osnma.get_size(field)
                    if n_field != osnma.get_data(field):
                        osnma.load(field, n_field)
                        print_read(osnma, field)

                if osnma.get_data('NB') != None:
                    if osnma.get_meaning('BID') >= osnma.get_meaning('NB'):
                        is_start_DSM = True

                if prev_dsm_id != osnma.get_data('DSM_ID'):
                    is_different_DSM = True
                elif osnma.get_meaning('BID') == 1:
                    is_different_DSM = False
                    print('Same DMS message as before\n')
            else:
                if osnma.get_data('DSM_ID', format='uint') < 12 and is_different_DSM:
                    # DMS-KROOT block
                    bit_count = 0
                    next_page = False
                    
                    for field in osnma.OSNMA_sections['DMS_KROOT'][section_pos:]:
                        # Load fields
                        if not middle_field:
                            if (bit_count + osnma.get_size(field)) <= hkroot_length:
                                # It fits
                                n_field = osnma_hkroot[bit_count:bit_count + osnma.get_size(field)]
                                bit_count += osnma.get_size(field)
                                section_pos += 1
                                osnma.load(field, n_field)

                                if bit_count == hkroot_length:
                                    next_page = True

                                print_read(osnma, field)

                            else:
                                # Start of new field that occupies more than this page
                                part_field = osnma_hkroot[bit_count:]
                                middle_field = True
                                current_size = hkroot_length - bit_count
                                next_page = True

                                print_reading(osnma, field, current_size)

                        else:
                            if (osnma.get_size(field) - current_size) > hkroot_length:
                                # Middle of field and still not finished in this page
                                part_field.append(osnma_hkroot)
                                current_size += hkroot_length
                                next_page = True

                                print_reading(osnma, field, current_size)

                            else:
                                # End assembling the field
                                middle_field = False
                                part_field.append(osnma_hkroot[:osnma.get_size(field)-current_size])
                                osnma.load(field, part_field)

                                bit_count += (osnma.get_size(field)-current_size)
                                section_pos += 1

                                if bit_count == hkroot_length:
                                    next_page = True               

                                print_read(osnma, field)

                        if next_page:
                            # All bites from current page read
                            break
        
        
            if is_new_subframe and is_start_DSM:
                if osnma.kroot_verification(pubk_path):
                    print('\n\t\033[1m\033[30m\033[42m Signature verified!\033[m\n')
                else:
                    print('\n\t\033[31m Bad Signature \033[m\n')

        if index >= 300:
            break

        else:
            pass

        








