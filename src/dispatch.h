#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

void dispatch(struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose);

pthread_mutex_t muxlock;

#endif
