import bitstring as bs
import osnma_receiver


default_path = 'scenarios/TV200_DsmKroot1/log/20200115_135442/NavMsg.csv'
pubk_path = 'scenarios/TV200_DsmKroot1/input/pk/pub_pem_256v1.pem'

if __name__ == "__main__":

    NPKT = '0b0001'
    NPKID = '0b0000'
    #max_iter = 195
    max_iter = 300
    gnss = 0
    svid = 1

    osnma_r = osnma_receiver.OSNMA_receiver(gnss, svid, default_path, pubk_path)
    osnma_r.osnma.load('NPKT', NPKT)
    osnma_r.osnma.load('NPKID', NPKID)

    osnma_r.gobrbrbr(max_iter)





