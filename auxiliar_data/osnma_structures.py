
class KeyEntry:
    
    def __init__(self, index, wn, tow, key):
        self.index = index
        self.wn = wn
        self.tow = tow
        self.key = key

pubk_lengths = {'ECDSA P-224': {'signature':448, 'npk':232},
                'ECDSA P-256': {'signature':512, 'npk':264},
                'ECDSA P-384': {'signature':768, 'npk':392},
                'ECDSA P-521': {'signature':1056, 'npk':536}}

section_structures = {
    'HKROOT': ['NMA_H', 'DSM_H', 'DMS_block'],
    'NMA_H': ['NMA_S', 'CID', 'CPKS'],
    'DSM_H': ['DSM_ID', 'BID'],
    'DMS_KROOT': ['NB', 'PKID', 'CIDKR', 'NMACK', 'HF', 'MF', 'KS',
            'MS', 'MACLT', 'rsvd', 'MO', 'KROOT_WN', 'KROOT_TOWH',
            'alpha', 'KROOT', 'DS', 'P1'],
    'DMS_PKR': ['NB', 'MID', 'ITN', 'NPKT', 'NPKID', 'NPK', 'P2']
}

cryptographic_structures = {
    'kroot_sm': ['NMA_H', 'CIDKR', 'NMACK', 'HF', 'MF',
            'KS', 'MS', 'MACLT', 'rsvd', 'MO', 'KROOT_WN', 'KROOT_TOWH',
            'alpha', 'KROOT'],
    'mac0_am': ['PRN', 'GST_WN', 'GST_TOW', 'CTR', 'NMA_S', 'navdata', 'P3'],
    'mac_am': ['PRN', 'PRN_A', 'GST_WN', 'GST_TOW', 'CTR', 'NMA_S', 'navdata', 'P3'],
    'pkr_m': ['NPKT', 'NPKTID', 'NPK'],
    'key_m': ['nKEY','GST','alpha','P3']
}

