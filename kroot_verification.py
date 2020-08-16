from auxiliar_data.test_data import KROOTVECTOR
import bitstring as bs
import osnma_core 

osnma = osnma_core.OSNMACore()

# Instanciate local structures

kroot_raw = bs.BitArray(KROOTVECTOR['decoded'])

osnma.OSNMA_data['DS'].size = KROOTVECTOR['DS_len']
osnma.OSNMA_data['NMA_H'].data = bs.BitArray(KROOTVECTOR['NMA_H'])

# Disfragment the raw message

bit_counter = 0
for field in osnma.OSNMA_sections['DMS_KROOT']:
    
    if field == 'P1':
        osnma.OSNMA_data[field].data = kroot_raw[bit_counter:]
    else:
        osnma.OSNMA_data[field].data = kroot_raw[bit_counter:bit_counter+osnma.OSNMA_data[field].size]
        bit_counter += osnma.OSNMA_data[field].size

        # Update size of the KROOT field
        if field == 'KS':
            osnma.OSNMA_data['KROOT'].size = osnma.OSNMA_data[field].meaning(osnma.OSNMA_data[field].data.uint)

osnma.kroot_verification()
