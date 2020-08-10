
class Field:
    def __init__(self, size, name, meaning=None):
        self.size = size
        self.name = name
        if meaning:
            self.meaning = meaning


NMA_S = Field(
    2,
    'NMA Status',
    lambda x : {0:'N/A', 1:'Test', 2:'Operational', 3:"Don't Use"}.get(x)
)

CID = Field(
    2,
    'Chain ID'
)

CPKS = Field(
    3,
    'Chain and Public Key Status',
    lambda x : {0:'Reserved', 1:'Nominal', 2:'EOC', 3:'CREV', 4:'NPK',
    5:'PKREV', 6:'Reserved', 7:'Reserved'}.get(x)
)

NMA_H = Field(
    8,
    'NMA Header'
)

DSM_H = Field(
    8,
    'DSM Header'
)

DSM_ID = Field(
    4,
    'DSM ID'
)

BID = Field(
    4,
    'DSM Block ID'
)

NB = Field(
    4,
    'Nb. of Blocks',
    lambda x : x+6 if (x != 0) and (x<11) else 'rsvd'
)

PKID = Field(
    4,
    'Public Key ID'
)

CIDKR = Field(
    2,
    'Chain ID of KROOT'
)

NMACK = Field(
    2,
    'Nb. of MACK blocks',
    lambda x : 0 if x == 0 else x
)

HF = Field(
    2,
    'Hash Function',
    lambda x : {0:'SHA-256', 1:'SHA3-224', 2:'SHA3-256', 3:'rsvd'}.get(x)
)

MF = Field(
    2,
    'MAC Function',
    lambda x : {0:'HMAC-SHA-256', 1:'CMAC-AES',2:'rsvd',3:'rsvd'}.get(x)
)

KS = Field(
    4,
    'Key Size',
    lambda x : {0:96,1:104,2:112,3:120,4:128,5:160,6:192,7:224,8:256,9:'rsvd',
            10:'rsvd',11:'rsvd',12:'rsvd',13:'rsvd',14:'rsvd',15:'rsvd'}.get(x)
)

MS = Field(
    4,
    'MAC Size',
    lambda x : {0:10,1:12,2:14,3:16,4:18,5:20,6:24,7:28,8:32,9:40,
            10:'rsvd',11:'rsvd',12:'rsvd',13:'rsvd',14:'rsvd',15:'rsvd'}.get(x)
)

MACLT = Field(
    8,
    'MAC Lookup Table'
)

rsvd = Field(
    2,
    'Reserved'
)

MO = Field(
    2,
    'MACK Offset',
    lambda x : {0:'No Offset', 1:'Offset', 2:'rsvd', 3:'rsvd'}.get(x)
)

KROOT_WN = Field(
    12,
    'KROOT Week Number'
)

KROOT_TOWH = Field(
    8,
    'KROOT Time of Week (hours)'
)

alpha = Field(
    48,
    'alpha'
)

KROOT = Field(
    None,
    'Key, size by KS'
)

DS = Field(
    None,
    'Digital Signature'
)

P1 = Field(
    None,
    'Padding bits for multiple of DMS block'
)

MID = Field(
    4,
    'Message ID'
)

ITN = Field(
    1024,
    'Intermediate Tree Nodes'
)

NPKT = Field(
    4,
    'New Public Key type',
    lambda x : {0:'ECDSA P-224', 1:'ECDSA P-256', 2:'ECDSA P-384',
            3:'ECDSA P-521', 4:'Emergency Service Message'}.get(x) if x<5 else 'rsvd'
)

NPKTID = Field(
    4,
    'New Public Key ID'
)

NPK = Field(
    None,
    'New Public Key'
)

P2 = Field(
    None,
    'Padding bits for multiple of DMS block'
)





    