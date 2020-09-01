
osnma-receiver
========

osnma-receiver contains a OSNMA_receiver class that implements a Galileo OSNMA receiver that works with nominal data.

The file scenario1.py can be executed out of the box and will start to read real satellite data and print to console the OSNMA operations done by the receiver.

If you are willing to intanciate your own receiver it can be done by:

    import osnma_receiver
    
    osnma_r = osnma_receiver.OSNMA_receiver(GSSS_system,
                                            SVID,
                                            path_to_csv,
                                            path_to_pubk,
                                            verbose_mack = True,
                                            verbose_headers = False,
                                            only_headers = False)
                                            
    osnma_r.osnma.load(<pre-loaded data such as NPKT or NPKID>)
    osnma_r.start(max_iterarion)

Features
--------

- Verifies KROOT, TESLA keys, MAC0 and MACSEQ messages.
- Accept csv files with the data.
- Uses osnma-core library.

Installation
------------

Clone or download this GitHub and install dependencies with:

  cd <git folder>
  pip install -r requirements.txt
  
  python3 run scenario1.py

Support
-------

If you are having issues, please let me know.

License
-------

The project is licensed under the GPLv3 license.
