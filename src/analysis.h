#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>
#include <stdbool.h>

void analyse(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose);

// declare global variables
extern bool syn_attack;
extern int num_syn;
extern int num_syn_ip;
extern double time_syn;
extern int arp_responses;
extern int url_violations;
extern unsigned long *source_ips;
//extern double *arrival_times;

#endif
