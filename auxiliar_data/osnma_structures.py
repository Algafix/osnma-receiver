
class KeyEntry:
    
    def __init__(self, index, wn, tow, key):
        self.index = index
        self.wn = wn
        self.tow = tow
        self.key = key

section_structures = {
    'HKROOT': ['NMA_H', 'DSM_H', 'DMS_block'],
    'NMA_H': ['NMA_S', 'CID', 'CPKS'],
    'DSM_H': ['DSM_ID', 'BID'],
    'DMS_KROOT': ['NB', 'PKID', 'CIDKR', 'NMACK', 'HF', 'MF', 'KS',
            'MS', 'MACLT', 'rsvd', 'MO', 'KROOT_WN', 'KROOT_TOWH',
            'alpha', 'KROOT', 'DS', 'P1'],
    'DMS_PKR': ['NB', 'MID', 'ITN', 'NPKT', 'NPKTID', 'NPK', 'P2']
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

