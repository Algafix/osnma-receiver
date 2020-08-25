import bitstring as bs
import osnma_receiver


default_path = 'scenarios/TV221_ChainRenewal/log/20200115_140039/NavMsg.csv'
pubk_path = 'scenarios/TV221_ChainRenewal/input/pk/pub_pem_256v1.pem'

if __name__ == "__main__":

    NPKT = '0b0001'
    NPKID = '0b0000'
    #max_iter = 195
    max_iter = 400
    gnss = 0
    svid = 1

    osnma_r = osnma_receiver.OSNMA_receiver(gnss, svid, default_path, pubk_path,'scenario2', verbose_mack=False)
    osnma_r.osnma.load('NPKT', NPKT)
    osnma_r.osnma.load('NPKID', NPKID)

    # Floatig key fast
    fkey_index = 207504
    fkey_gst_WN = bs.BitArray(uint=1018, length=12)
    fkey_gst_TOW = bs.BitArray(uint=432030, length=20)
    fkey = bs.BitArray(hex='f1447e41fa7d309f5700017ab2eaa57d')
    osnma_r.osnma.load_floating_key(fkey_index, fkey_gst_WN, fkey_gst_TOW, fkey)

    osnma_r.gobrbrbr(max_iter)