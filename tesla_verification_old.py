import hashlib
#from append_hex import append_hex


K2 = 0x22B30FBEE8C6C4A43480AF28A67D4A65
GST = 0x3B369780
alpha = 0xF1CA3856A975

print("\n========================================")

concat = int(format(K2,'x')+format(GST,'x')+format(alpha,'x'),16)
print(hex(concat))

m = hashlib.sha256()

m.update(bytearray.fromhex('22B30FBEE8C6C4A43480AF28A67D4A653B369780F1CA3856A975'))

print(m.hexdigest())

