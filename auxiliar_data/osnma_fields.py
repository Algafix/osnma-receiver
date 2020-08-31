

class Field:
    """Class that stores an OSNMA field: data, name, size, description and meaning.
    """
    def __init__(self, size, name, description, meaning=None, data=None, repr=None):
        self.size = size
        self.name = name
        self.description = description
        self.meaning = meaning
        self.data = data
        self.repr = repr
    
    def get_meaning(self):
        if self.repr == 'hex':
            return self.data.hex if self.meaning == None else self.meaning(self.data.uint)
        else:
            return self.data.uint if self.meaning == None else self.meaning(self.data.uint)
    
    def get_data(self):
        return self.data
    
    def get_data_uint(self):
        return self.data.uint
    
    def get_data_bytes(self):
        return self.data.bytes
    
    def set_data(self, data):
        self.data = data
    
    def get_description(self):
        return self.description
    
    def get_repr(self):
        return self.repr

    def get_size(self):
        return self.size
    
    def set_size(self, size):
        self.size = size

OSNMA_fields = {

    'NMA_S' : Field(
        2,
        'NMA_S',
        'NMA Status',
        lambda x : {0:'N/A', 1:'Test', 2:'Operational', 3:"Don't Use"}.get(x)
    ),

    'CID' : Field(
        2,
        'CID',
        'Chain ID'
    ),

    'CPKS' : Field(
        3,
        'CPKS',
        'Chain and Public Key Status',
        lambda x : {0:'Reserved', 1:'Nominal', 2:'EOC', 3:'CREV', 4:'NPK',
        5:'PKREV', 6:'Reserved', 7:'Reserved'}.get(x)
    ),

    'NMA_H' : Field(
        8,
        'NMA_H',
        'NMA Header'
    ),

    'DSM_H' : Field(
        8,
        'DMS_H',
        'DSM Header'
    ),

    'DSM_ID' : Field(
        4,
        'DMS_ID',
        'DSM ID',
        lambda x : 'DMS-KROOT ID' if x < 12 else 'DMS-PKR ID'
    ),

    'BID' : Field(
        4,
        'BID',
        'DSM Block ID',
        lambda x : x+1
    ),

    'NB' : Field(
        4,
        'NB',
        'Nb. of Blocks',
        lambda x : x+6 if (x != 0) and (x<11) else 'rsvd'
    ),

    'PKID' : Field(
        4,
        'PKID',
        'Public Key ID'
    ),

    'CIDKR' : Field(
        2,
        'CIDKR',
        'Chain ID of KROOT'
    ),

    'NMACK' : Field(
        2,
        'NMACK',
        'Nb. of MACK blocks',
        lambda x : {0:'rsvd', 1:480, 2:240, 3:160}.get(x)
    ),

    'HF' : Field(
        2,
        'HF',
        'Hash Function',
        lambda x : {0:'SHA256', 1:'SHA3_224', 2:'SHA3_256', 3:'rsvd'}.get(x)
    ),

    'MF' : Field(
        2,
        'MF',
        'MAC Function',
        lambda x : {0:'HMAC-SHA-256', 1:'CMAC-AES',2:'rsvd',3:'rsvd'}.get(x)
    ),

    'KS' : Field(
        4,
        'KS',
        'Key Size',
        lambda x : {0:96,1:104,2:112,3:120,4:128,5:160,6:192,7:224,8:256,9:'rsvd',
                10:'rsvd',11:'rsvd',12:'rsvd',13:'rsvd',14:'rsvd',15:'rsvd'}.get(x)
    ),

    'MS' : Field(
        4,
        'MS',
        'MAC Size',
        lambda x : {0:10,1:12,2:14,3:16,4:18,5:20,6:24,7:28,8:32,9:40,
                10:'rsvd',11:'rsvd',12:'rsvd',13:'rsvd',14:'rsvd',15:'rsvd'}.get(x)
    ),

    'MACLT' : Field(
        8,
        'MACLT',
        'MAC Lookup Table'
    ),

    'rsvd' : Field(
        2,
        'rsvd',
        'Reserved'
    ),

    'MO' : Field(
        2,
        'MO',
        'MACK Offset',
        lambda x : {0:'No Offset', 1:'Offset', 2:'rsvd', 3:'rsvd'}.get(x)
    ),

    'KROOT_WN' : Field(
        12,
        'KROOT_WN',
        'KROOT Week Number'
    ),

    'KROOT_TOWH' : Field(
        8,
        'KROOT_TOWH',
        'KROOT Time of Week (hours)'
    ),

    'alpha' : Field(
        48,
        'alpha',
        'alpha',
        repr='hex'
    ),

    'KROOT' : Field(
        None,
        'KROOT',
        'Key Root',
        repr='hex'
    ),

    'DS' : Field(
        None,
        'DS',
        'Digital Signature',
        repr='hex'
    ),

    'P1' : Field(
        None,
        'P1',
        'Padding bits for multiple of DMS block'
    ),

    'MID' : Field(
        4,
        'MID',
        'Message ID'
    ),

    'ITN' : Field(
        1024,
        'ITN',
        'Intermediate Tree Nodes',
        repr='hex'
    ),

    'NPKT' : Field(
        4,
        'NPKT',
        'New Public Key type',
        lambda x : {0:'ECDSA P-224', 1:'ECDSA P-256', 2:'ECDSA P-384',
                3:'ECDSA P-521', 4:'Emergency Service Message'}.get(x) if x<5 else ('rsvd',None)
    ),

    'NPKID' : Field(
        4,
        'NPKID',
        'New Public Key ID'
    ),

    'NPK' : Field(
        None,
        'NPK',
        'New Public Key',
        repr='hex'
    ),

    'P2' : Field(
        None,
        'P2',
        'Padding bits for multiple of DMS block'
    ),

    'P3' : Field(
        1,
        'P3',
        'Padding bits for multiple of byte in MAC'
    ),

    'PRN' : Field(
        8,
        'PRN',
        'Number of the satellite transmiting'
    ),

    'CTR' : Field(
        8,
        'CTR',
        'Counter of MACs per block'
    ),

    'GST_WN' : Field(
        12,
        'GST_WN',
        'GST Week number'
    ),

    'GST_TOW' : Field(
        20,
        'GST_TOW',
        'GST Time of Week'
    ),

    'navdata' : Field(
        None,
        'navdata',
        'Navigation Data within the MAC',
        repr='hex'
    )
}