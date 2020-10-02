# IntrusionDetection
Intrusion detection system designed in C.

In order to implement this system, a number of design choices were made prior to starting
any programming. 

Firstly, as the code needed to work for a Linux environment, the use of a virtual machine was required. Another design choice was the
threading strategy that would allow the system to handle high data rates and make the system
multi-threaded. It was decided that the system implements the ‘One Thread per X’ model
which creates a new thread for each packet to process. Its simplicity allowed
for clear implementation and was more practical for testing due to its low overhead.

Having established design choices for the system, a clear structure was laid out for the code
in order to be efficient and avoid unnecessary complications later in development. With the
assistance of the network primer page, it was decided that the ethernet header would be
parsed first in order to obtain the ethernet type of the packet. From the ethernet type, the
system should be able to differentiate between IP headers and ARP headers in order to
parse the network layer. If the protocol of the IP header is TCP, then the system should
proceed to parse the TCP header.

To test the detection of a SYN flood attack, an attack was generated on the
loopback interface (-lo) with the following command:
``
hping3 -c #OFPACKETS -d 120 -S -w 64 -p 80 -i u100 --rand-source localhost
``
