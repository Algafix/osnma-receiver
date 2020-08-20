import hashlib
from auxiliar_data.test_data import TESTVECTOR


def key_calculation(key, GST, alpha, KS):
    m = hashlib.sha256()
    m.update(key + GST + alpha)
    return m.digest()[:KS//8]

# Initialization of common values for the chain verification

key_chain = TESTVECTOR['keychain']
KS = TESTVECTOR['KS']
TOW_S = TESTVECTOR['TOWS']
alpha = bytearray.fromhex(TESTVECTOR['alpha'])

# The last appended key in the chain is checked agaist the previous ones

last_key = bytearray.fromhex(key_chain[-1]['KEY'])

for key_info in reversed(key_chain[:-1]):

    # Extraction of values to improve readability
    WN = key_info['WN']
    TOW = key_info['TOW']
    current_key = bytearray.fromhex(key_info['KEY'])

    # In the test data the GST 32 bits register is fragmented onto WN and TOW,
    # so it's necessary to re-unite it by bit alignment.
    GST = bytearray.fromhex(format(WN<<TOW_S|TOW,'x'))
    
    computed_key = key_calculation(last_key,GST,alpha,KS)

    print('\n==========================================')
    print('Current key: ' + current_key.hex())
    print('Computed key: ' + computed_key.hex())
    if (current_key == computed_key):
        last_key = current_key
        print('\t\033[32m Same Key! \033[m')
        if(key_info['ID'] == 0):
            print('\n\t\033[1m\033[30m\033[42m Chain verified! \033[m')
    else:
        print('\t\033[31m Keys are diferent! \033[m')
        break

print('\n==========================================')