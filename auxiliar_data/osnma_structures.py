
class KeyEntry:
    """Class that contains all the information related to a key in
    the TESLA chain. These information being it's index, week number,
    time of the week and the key itself.
    """
    
    def __init__(self, index, wn, tow, key):
        self.index = index
        self.wn = wn
        self.tow = tow
        self.key = key
    
    def get_as_dict(self):
        return {'Index':self.index, 'WN':self.wn.uint, 'TOW':self.tow.uint, 'Key':self.key.hex}

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
    'mac_am': ['PRN', 'PRN_N', 'GST_WN', 'GST_TOW', 'CTR', 'NMA_S', 'navdata', 'P3'],
    'pkr_m': ['NPKT', 'NPKID', 'NPK'],
    'key_m': ['nKEY','GST','alpha','P3']
}

mac_lookup_table = [
    {
        'ID': 0,
        'sections': 1,
        'NMACK': 1,
        'MACs': 14,
        'sequence': ['00S','00E','00E','00E','00E','00E','00E','00S','00E','00E','00E','00E','00E','00E']
    },
    {
        'ID': 1,
        'sections': 1,
        'NMACK': 1,
        'MACs': 14,
        'sequence': ['00S','00G','00G','00G','00G','00E','00E','00E','00E','00E','00E','00S','00G','00G']
    },
    {
        'ID': 2,
        'sections': 1,
        'NMACK': 1,
        'MACs': 14,
        'sequence': ['00S','FLX','FLX','FLX','FLX','FLX','FLX','FLX','FLX','FLX','FLX','FLX','FLX','FLX']
    },
    {
        'ID': 3,
        'sections': 1,
        'NMACK': 1,
        'MACs': 14,
        'sequence': ['00S','04S','03S','00E','00E','00E','00E','FLX','FLX','FLX','11S','12S','FLX','FLX']
    },
    {
        'ID': 4,
        'sections': 1,
        'NMACK': 1,
        'MACs': 14,
        'sequence': ['00S','04S','03S','00G','00G','00E','00E','FLX','FLX','FLX','11S','12S','FLX','FLX']
    },
    {
        'ID': 5,
        'sections': 1,
        'NMACK': 1,
        'MACs': 14,
        'sequence': ['00S','03S','05S','00E','FLX','04S','05G','00E','FLX','05E','12S','11S','FLX','FLX']
    },
    {
        'ID': 6,
        'sections': 1,
        'NMACK': 1,
        'MACs': 14,
        'sequence': ['00S','03S','05S','00E','04S','05E','FLX','12S','FLX','FLX','FLX','FLX','FLX','FLX']
    },
    {
        'ID': 7,
        'sections': 1,
        'NMACK': 1,
        'MACs': 14,
        'sequence': ['00S','FLX','FLX','FLX','00E','00E','00E','FLX','FLX','FLX','11S','12S','FLX','FLX']
    },
    {
        'ID': 8,
        'sections': 1,
        'NMACK': 2,
        'MACs': 5,
        'sequence': [['00S','00E','00E','00E','00E'],['00S','00E','00E','00E','00E']]
    },
    {
        'ID': 9,
        'sections': 1,
        'NMACK': 2,
        'MACs': 5,
        'sequence': [['00S','00G','00G','00G','00G'],['00S','00E','00E','00E','00E']]
    },
    {
        'ID': 10,
        'sections': 1,
        'NMACK': 2,
        'MACs': 5,
        'sequence': [['00S','FLX','FLX','FLX','FLX'],['00S','00E','00E','00E','00E']]
    },
    {
        'ID': 11,
        'sections': 1,
        'NMACK': 2,
        'MACs': 5,
        'sequence': [['00S','FLX','FLX','00E','11S'],['00S','00E','00E','00E','12S']]
    },
    {
        'ID': 12,
        'sections': 1,
        'NMACK': 2,
        'MACs': 5,
        'sequence': [['00S','FLX','FLX','00G','11S'],['00S','00G','00E','00E','12S']]
    },
    {
        'ID': 13,
        'sections': 1,
        'NMACK': 2,
        'MACs': 5,
        'sequence': [['00S','03S','05S','FLX','00E'],['05E','00E','04S','00E','12S']]
    },
    {
        'ID': 14,
        'sections': 1,
        'NMACK': 2,
        'MACs': 5,
        'sequence': [['00S','03S','05S','FLX','00E'],['05E','05G','04S','00G','12S']]
    },
    {
        'ID': 15,
        'sections': 1,
        'NMACK': 2,
        'MACs': 5,
        'sequence': [['00S','04S','FLX','FLX','11S'],['00S','00E','00E','00E','12S']]
    },
    {
        'ID': 16,
        'sections': 1,
        'NMACK': 2,
        'MACs': 5,
        'sequence': [['00S','12S','00E','00E','FLX'],['00S','11S','00E','00E','00E']]
    },
    {
        'ID': 17,
        'sections': 1,
        'NMACK': 2,
        'MACs': 5,
        'sequence': [['00S','FLX','FLX','00G','FLX'],['00S','00E','00E','12S','11S']]
    },
    {
        'ID': 18,
        'sections': 2,
        'NMACK': 3,
        'MACs': 2,
        'sequence': [[['00S','00E'], ['00E','00E'], ['00E','00E']],[['00S','00E'], ['00E','00E'], ['00E','00E']]]
    },
    {
        'ID': 19,
        'sections': 2,
        'NMACK': 3,
        'MACs': 2,
        'sequence': [[['00S','00G'], ['00G','00G'], ['00G','00G']],[['00S','00E'], ['00E','00E'], ['00E','00E']]]
    },
    {
        'ID': 20,
        'sections': 2,
        'NMACK': 3,
        'MACs': 2,
        'sequence': [[['00S','FLX'], ['00E','00E'], ['00E','00E']],[['00S','FLX'], ['00E','00E'], ['00E','00E']]]
    },
    {
        'ID': 21,
        'sections': 2,
        'NMACK': 3,
        'MACs': 2,
        'sequence': [[['00S','FLX'], ['00E','00E'], ['00E','11S']],[['00S','FLX'], ['00E','00E'], ['00E','12S']]]
    },
    {
        'ID': 22,
        'sections': 2,
        'NMACK': 3,
        'MACs': 2,
        'sequence': [[['00S','FLX'], ['00G','00G'], ['00G','11S']],[['00S','FLX'], ['00E','00E'], ['00E','12S']]]
    },
    {
        'ID': 23,
        'sections': 2,
        'NMACK': 3,
        'MACs': 2,
        'sequence': [[['00S','FLX'], ['05S','03S'], ['00E','11S']],[['00S','FLX'], ['04S','00E'], ['05E','12S']]]
    },
    {
        'ID': 24,
        'sections': 2,
        'NMACK': 3,
        'MACs': 2,
        'sequence': [[['00S','FLX'], ['05S','03S'], ['00G','11S']],[['00S','FLX'], ['04S','00G'], ['05E','12S']]]
    }
]

adkd_masks = [
    [
        {
            'word': 1,
            'page': 10,
            'bits': [(8,114),(122,136)]
        },
        {
            'word': 2,
            'page': 0,
            'bits': [(8,114),(122,136)]
        },
        {
            'word': 3,
            'page': 11,
            'bits': [(8,114),(122,138)]
        },
        {
            'word': 4,
            'page': 1,
            'bits': [(8,114),(122,136)]
        },
        {
            'word': 5,
            'page': 12,
            'bits': [(8,75)]
        }
    ]
]

