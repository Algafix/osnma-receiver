
TESTVECTOR = {

    'KS': 128,
    'MS': 12,
    'GSTS': 32,
    'WNS': 12,
    'TOWS': 20,
    'alpha': 'F1CA3856A975',
    'keychain': [
        {
            'ID': 0,
            'WN': 947,
            'TOW': 431970,
            'KEY': 'EE6772D9AB8396866DC57EADA1D29637'
        },
        {
            'ID': 1,
            'WN': 947,
            'TOW': 432000,
            'KEY': '81AEE575195E13C06961A705A191B9CD'
        },
        {
            'ID': 2,
            'WN': 947,
            'TOW': 432000,
            'KEY': '22B30FBEE8C6C4A43480AF28A67D4A65'
        }
    ]
}

KROOTVECTOR = {
    'decoded': '0x2020410B03B378F1CA3856A975EE6772D9AB8396866DC57EADA1D2963715E81EE289C9F6F54869405F5E115E424777D11D598D2451CC576C2837A3984715B22FD153EF85179EA6D4BD0101DB1C0E363A19DCA1625034F2CCF9D0E763E3A442FF8199A7D3C8CEF9B2',
    'DS_len': 512,
    'NMA_H': '0b10000010'
}

MAC0VECTOR = {
    'MAC0': {
            'TAG0': '0b111001011000',
            'SEQ': '0b110000100100',
            'IOD': '0b0000'
            },
    'PRN': '0b00010010',
    'GST_WN': '0b001110110011',
    'GST_TOW': '0b01101001011110011110',
    'CTR': '0b00000001',
    'NMA_S': '0b10',
    'navdata': '0b000101000001110000100000001100110100011100000000000011010000000000000000000000000000000010101010000001001011010010100100000101000010100001111011111110101010010010001001111101001001111101001010000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110010001010000010010000000000000000000000000000000000111000010000000000000000000000000000000000000000000000000000000000000000011001000000000000000000000000000000000000000000000000000000000000',
    'P3': '0b0',
    'KEY': '0x4E0E2DA7F80F547B874D4A2533316389',
    'KS': 128,
    'MACLT': 11,
    'MS': 12
}

NAVDATA = ['0x0214287BFAA489F49F4A0000000000',
            '0x80006091123D022AAAAA4CCEED08C0',
            '0x041412000000007080000000000000',
            '0x800040D2C280096AAAAA63755748C0',
            '0x06000000000000001278B3B1424D00',
            '0xAF0AB3B444011EEAAAAA785A6608C0',
            '0x070ED04C0000000000007BA2800580',
            '0x93355740403A62AAAAAA4FD814C8C0',
            '0x08000000000280000000000003DD00',
            '0x940029A1FCFB512AAAAA52EB5848C0',
            '0x0C0204081020408102040800000000',
            '0x80008E5CE339EBAAAAAA51D24948C0',
            '0x0E0000000000000000000000000000',
            '0x80002C68E8E3446AAAAA47B452C8C0',
            '0x0B8802040810204081020408102040',
            '0x8081794BEE39C86AAAAA646AB788C0',
            '0x0D0000023B36978000000000000000',
            '0x800039C800AA80EAAAAA4DC46CC8C0',
            '0x0F0000000000000000000000000680',
            '0x97935F80003C682AAAAA68067BC8C0',
            '0x01141C203347000D00000000AA0480',
            '0xB4A48540AD06C02AAAAA5C8FF248C0',
            '0x031400000000000000000000000000',
            '0x8006707E8D4EF8EAAAAA765C45C8C0',
            '0x0532000000000000000766D2F32A80',
            '0xAAAA9844C78F936AAAAA7121B188C0',
            '0x0095555555555555555555554ECD80',
            '0xA5E6E8666C215C6AAAAA403ED148C0',
            '0x0095555555555555555555554ECD80',
            '0xA5E74F4AD42E5DAAAAAA5E2B6D88C0'
]

PKRVECTOR = '0x70A5E09C16A42D37D584D63797D684ED5D24F12CF99553033B01FACBBC79EEBF9C743A5BC50897F9A5E78FB0733D425B541874398ABB0E12DD6C2D585035ECBF09C978D80C3F476D3D5B7129003F735CB5019E995BB9FB6CF7045CCFF0039965F775943C3286BA8222E1B6437D12507436C0BF38BBBB5FD856D9D948EF8FB3BAEC0002D25BDF123D1CB876022BD071BC2372E4132DC62E627C1988D4E7272619148C51B7F0EED951EA'
MERKLEROOT = '0x5E53B01CC55A978180040E95AB129F2E2C4B65CBDFA849E4DE9E26AC7315A49D'



# Old sniped

# OSNMA_data = {

#     'NMA_S' : Field(
#         2,
#         'NMA_S',
#         'NMA Status',
#         lambda x : {0:'N/A', 1:'Test', 2:'Operational', 3:"Don't Use"}.get(x)
#     ),

#     'CID' : Field(
#         2,
#         'CID',
#         'Chain ID'
#     ),

#     'CPKS' : Field(
#         3,
#         'CPKS',
#         'Chain and Public Key Status',
#         lambda x : {0:'Reserved', 1:'Nominal', 2:'EOC', 3:'CREV', 4:'NPK',
#         5:'PKREV', 6:'Reserved', 7:'Reserved'}.get(x)
#     ),

#     'NMA_H' : Field(
#         8,
#         'NMA_H',
#         'NMA Header'
#     ),

#     'DSM_H' : Field(
#         8,
#         'DMS_H',
#         'DSM Header'
#     ),

#     'DSM_ID' : Field(
#         4,
#         'DMS_ID',
#         'DSM ID'
#     ),

#     'BID' : Field(
#         4,
#         'BID',
#         'DSM Block ID'
#     ),

#     'NB' : Field(
#         4,
#         'NB',
#         'Nb. of Blocks',
#         lambda x : x+6 if (x != 0) and (x<11) else 'rsvd'
#     ),

#     'PKID' : Field(
#         4,
#         'PKID',
#         'Public Key ID'
#     ),

#     'CIDKR' : Field(
#         2,
#         'CIDKR',
#         'Chain ID of KROOT'
#     ),

#     'NMACK' : Field(
#         2,
#         'NMACK',
#         'Nb. of MACK blocks',
#         lambda x : 0 if x == 0 else x
#     ),

#     'HF' : Field(
#         2,
#         'HF',
#         'Hash Function',
#         lambda x : {0:'SHA-256', 1:'SHA3-224', 2:'SHA3-256', 3:'rsvd'}.get(x)
#     ),

#     'MF' : Field(
#         2,
#         'MF',
#         'MAC Function',
#         lambda x : {0:'HMAC-SHA-256', 1:'CMAC-AES',2:'rsvd',3:'rsvd'}.get(x)
#     ),

#     'KS' : Field(
#         4,
#         'KS',
#         'Key Size',
#         lambda x : {0:96,1:104,2:112,3:120,4:128,5:160,6:192,7:224,8:256,9:'rsvd',
#                 10:'rsvd',11:'rsvd',12:'rsvd',13:'rsvd',14:'rsvd',15:'rsvd'}.get(x)
#     ),

#     'MS' : Field(
#         4,
#         'MS',
#         'MAC Size',
#         lambda x : {0:10,1:12,2:14,3:16,4:18,5:20,6:24,7:28,8:32,9:40,
#                 10:'rsvd',11:'rsvd',12:'rsvd',13:'rsvd',14:'rsvd',15:'rsvd'}.get(x)
#     ),

#     'MACLT' : Field(
#         8,
#         'MACLT',
#         'MAC Lookup Table'
#     ),

#     'rsvd' : Field(
#         2,
#         'rsvd',
#         'Reserved'
#     ),

#     'MO' : Field(
#         2,
#         'MO',
#         'MACK Offset',
#         lambda x : {0:'No Offset', 1:'Offset', 2:'rsvd', 3:'rsvd'}.get(x)
#     ),

#     'KROOT_WN' : Field(
#         12,
#         'KROOT_WN',
#         'KROOT Week Number'
#     ),

#     'KROOT_TOWH' : Field(
#         8,
#         'KROOT_TOWH',
#         'KROOT Time of Week (hours)'
#     ),

#     'alpha' : Field(
#         48,
#         'alpha',
#         'alpha'
#     ),

#     'KROOT' : Field(
#         None,
#         'KROOT',
#         'Key, size by KS'
#     ),

#     'DS' : Field(
#         None,
#         'DS',
#         'Digital Signature'
#     ),

#     'P1' : Field(
#         None,
#         'P1',
#         'Padding bits for multiple of DMS block'
#     ),

#     'MID' : Field(
#         4,
#         'MID',
#         'Message ID'
#     ),

#     'ITN' : Field(
#         1024,
#         'ITN',
#         'Intermediate Tree Nodes'
#     ),

#     'NPKT' : Field(
#         4,
#         'NPKT',
#         'New Public Key type',
#         lambda x : {0:('ECDSA P-224',232), 1:('ECDSA P-256',264), 2:('ECDSA P-384',392),
#                 3:('ECDSA P-521',536), 4:('Emergency Service Message',None)}.get(x) if x<5 else ('rsvd',None)
#     ),

#     'NPKTID' : Field(
#         4,
#         'NPKTID',
#         'New Public Key ID'
#     ),

#     'NPK' : Field(
#         None,
#         'NPK',
#         'New Public Key'
#     ),

#     'P2' : Field(
#         None,
#         'P2',
#         'Padding bits for multiple of DMS block'
#     ),

#     'P3' : Field(
#         1,
#         'P3',
#         'Padding bits for multiple of byte in MAC'
#     ),

#     'PRN' : Field(
#         8,
#         'PRN',
#         'Number of the satellite transmiting'
#     ),

#     'CTR' : Field(
#         8,
#         'CTR',
#         'Counter of MACs per block'
#     ),

#     'GST_WN' : Field(
#         12,
#         'GST_WN',
#         'GST Week number'
#     ),

#     'GST_TOW' : Field(
#         20,
#         'GST_TOW',
#         'GST Time of Week'
#     ),

#     'navdata' : Field(
#         None,
#         'navdata',
#         'Navigation Data within the MAC'
#     )
# }