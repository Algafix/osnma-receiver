import osnma_core

osnma = osnma_core.OSNMACore()

osnma.OSNMA_data['NMA_H'].data = 'hola'

print(osnma.kroot_verification())

