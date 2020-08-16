from enum import IntEnum


# class DataField:
#     def __init__(self, field, data=None):
#         if isinstance(field, Field):
#             self.size = field.size
#             self.name = field.name
#             self.description = field.description
#             self.meaning = field.meaning
#             self.data
#         else:
#             raise TypeError(str(field) + " is not a Field object")

#         if data:
#             self.data = data

class Field:
    def __init__(self, size, name, description, meaning=None, data=None):
        self.size = size
        self.name = name
        self.description = description
        self.meaning = meaning
        self.data = data


NMA_S = Field(
    2,
    'NMA_S',
    'NMA Status',
    lambda x : {0:'N/A', 1:'Test', 2:'Operational', 3:"Don't Use"}.get(x)
)

CID = Field(
    2,
    'CID',
    'Chain ID'
)

CPKS = Field(
    3,
    'CPKS',
    'Chain and Public Key Status',
    lambda x : {0:'Reserved', 1:'Nominal', 2:'EOC', 3:'CREV', 4:'NPK',
    5:'PKREV', 6:'Reserved', 7:'Reserved'}.get(x)
)

NMA_H = Field(
    8,
    'NMA_H',
    'NMA Header'
)

DSM_H = Field(
    8,
    'DMS_H',
    'DSM Header'
)

DSM_ID = Field(
    4,
    'DMS_ID',
    'DSM ID'
)

BID = Field(
    4,
    'BID',
    'DSM Block ID'
)

NB = Field(
    4,
    'NB',
    'Nb. of Blocks',
    lambda x : x+6 if (x != 0) and (x<11) else 'rsvd'
)

PKID = Field(
    4,
    'PKID',
    'Public Key ID'
)

CIDKR = Field(
    2,
    'CIDKR',
    'Chain ID of KROOT'
)

NMACK = Field(
    2,
    'NMACK',
    'Nb. of MACK blocks',
    lambda x : 0 if x == 0 else x
)

HF = Field(
    2,
    'HF',
    'Hash Function',
    lambda x : {0:'SHA-256', 1:'SHA3-224', 2:'SHA3-256', 3:'rsvd'}.get(x)
)

MF = Field(
    2,
    'MF',
    'MAC Function',
    lambda x : {0:'HMAC-SHA-256', 1:'CMAC-AES',2:'rsvd',3:'rsvd'}.get(x)
)

KS = Field(
    4,
    'KS',
    'Key Size',
    lambda x : {0:96,1:104,2:112,3:120,4:128,5:160,6:192,7:224,8:256,9:'rsvd',
            10:'rsvd',11:'rsvd',12:'rsvd',13:'rsvd',14:'rsvd',15:'rsvd'}.get(x)
)

MS = Field(
    4,
    'MS',
    'MAC Size',
    lambda x : {0:10,1:12,2:14,3:16,4:18,5:20,6:24,7:28,8:32,9:40,
            10:'rsvd',11:'rsvd',12:'rsvd',13:'rsvd',14:'rsvd',15:'rsvd'}.get(x)
)

MACLT = Field(
    8,
    'MACLT',
    'MAC Lookup Table'
)

rsvd = Field(
    2,
    'rsvd',
    'Reserved'
)

MO = Field(
    2,
    'MO',
    'MACK Offset',
    lambda x : {0:'No Offset', 1:'Offset', 2:'rsvd', 3:'rsvd'}.get(x)
)

KROOT_WN = Field(
    12,
    'KROOT_WN',
    'KROOT Week Number'
)

KROOT_TOWH = Field(
    8,
    'KROOT_TOWH',
    'KROOT Time of Week (hours)'
)

alpha = Field(
    48,
    'alpha',
    'alpha'
)

KROOT = Field(
    None,
    'KROOT',
    'Key, size by KS'
)

DS = Field(
    None,
    'DS',
    'Digital Signature'
)

P1 = Field(
    None,
    'P1',
    'Padding bits for multiple of DMS block'
)

MID = Field(
    4,
    'MID',
    'Message ID'
)

ITN = Field(
    1024,
    'ITN',
    'Intermediate Tree Nodes'
)

NPKT = Field(
    4,
    'NPKT',
    'New Public Key type',
    lambda x : {0:('ECDSA P-224',232), 1:('ECDSA P-256',264), 2:('ECDSA P-384',392),
            3:('ECDSA P-521',536), 4:('Emergency Service Message',None)}.get(x) if x<5 else ('rsvd',None)
)

NPKTID = Field(
    4,
    'NPKTID',
    'New Public Key ID'
)

NPK = Field(
    None,
    'NPK',
    'New Public Key'
)

P2 = Field(
    None,
    'P2',
    'Padding bits for multiple of DMS block'
)

P3 = Field(
    1,
    'P3',
    'Padding bits for multiple of byte in MAC'
)

PRN = Field(
    8,
    'PRN',
    'Number of the satellite transmiting'
)

CTR = Field(
    8,
    'CTR',
    'Counter of MACs per block'
)

GST_WN = Field(
    12,
    'GST_WN',
    'GST Week number'
)

GST_TOW = Field(
    20,
    'GST_TOW',
    'GST Time of Week'
)

navdata = Field(
    None,
    'navdata',
    'Navigation Data within the MAC'
)

section_strutures = {
    'NMA_H': [NMA_S, CID,CPKS],
    'DSM_H': [DSM_ID, BID],
    'DMS_KROOT': [NB, PKID, CIDKR, NMACK, HF, MF, KS,
            MS, MACLT, rsvd, MO, KROOT_WN, KROOT_TOWH, alpha, KROOT, DS, P1],
    'DMS_PKR': [NB, MID, ITN, NPKT, NPKTID, NPK, P2]
}

class DMS_PKR_POS(IntEnum):
    NB = 0
    MID = 1
    ITN = 2
    NPKT = 3
    NPKTID = 4
    NPK = 5
    P2 = 6

class DMS_KROOT_POS(IntEnum):
    NB = 0
    PKID = 1
    CIDKR = 2
    NMACK = 3
    HF = 4
    MF = 5
    KS = 6
    MS = 7
    MACLT = 8
    rsvd = 9
    MO = 10
    KROOT_WN = 11
    KROOT_TOWH = 12
    alpha = 13
    KROOT = 14
    DS = 15
    P1 = 16


kroot_sm = [NMA_H, DMS_KROOT_POS.CIDKR, DMS_KROOT_POS.NMACK, DMS_KROOT_POS.HF, DMS_KROOT_POS.MF,
            DMS_KROOT_POS.KS, DMS_KROOT_POS.MS, DMS_KROOT_POS.MACLT, DMS_KROOT_POS.rsvd, DMS_KROOT_POS.MO,
            DMS_KROOT_POS.KROOT_WN, DMS_KROOT_POS.KROOT_TOWH, DMS_KROOT_POS.alpha, DMS_KROOT_POS.KROOT]

mac0_am = [PRN, GST_WN, GST_TOW, CTR, NMA_S, navdata, P3]

    