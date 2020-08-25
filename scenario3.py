import bitstring as bs
import osnma_receiver


default_path = 'scenarios/TV223_PublicKeyRenewal/log/20200116_083736/NavMsg.csv'
pubk_path = 'scenarios/TV223_PublicKeyRenewal/input/pk/pub_pem_256v1.pem'

if __name__ == "__main__":

    NPKT = '0b0001'
    NPKID = '0b0000'
    #max_iter = 195
    max_iter = 300
    gnss = 0
    svid = 1

    osnma_r = osnma_receiver.OSNMA_receiver(gnss, svid, default_path, pubk_path,'scenario3', verbose_mack=True)
    osnma_r.osnma.load('NPKT', NPKT)
    osnma_r.osnma.load('NPKID', NPKID)

    osnma_r.gobrbrbr(max_iter)





