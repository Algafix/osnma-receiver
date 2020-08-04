import hashlib
from test_data import *


def key_calculation(key, GST, alpha, KS):
    m = hashlib.sha256()
    m.update(key + GST + alpha)
    return bytearray.fromhex(m.hexdigest())[:KS//8]


key_chain = TESTVECTOR['keychain']
KS = TESTVECTOR['KS']
TOW_S = TESTVECTOR['TOWS']
alpha = bytearray.fromhex(TESTVECTOR['alpha'])


previous_key = bytearray.fromhex(key_chain[-1]['KEY'])

for key_info in reversed(key_chain[:-1]):

    WN = key_info['WN']
    TOW = key_info['TOW']
    GST = bytearray.fromhex(format(WN<<TOW_S|TOW,'x'))
    current_key = bytearray.fromhex(key_info['KEY'])
    computed_key = key_calculation(previous_key,GST,alpha,KS)

    print('\n==========================================')
    print('Current key: ' + current_key.hex())
    print('Computed key: ' + computed_key.hex())
    if (current_key == computed_key):
        previous_key = current_key
        print('\t\033[32m Same Key! \033[m')
        if(key_info['ID'] == 0):
            print('\n\t\033[1m\033[30m\033[42m Chain verifiyed! \033[m')
    else:
        print('\t\033[31m Keys are diferent! \033[m')
        break

print('==========================================')