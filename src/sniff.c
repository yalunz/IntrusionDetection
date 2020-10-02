#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include <signal.h>
#include "analysis.h"
#include "dispatch.h"

// signal handler to handle ^C 
void signal_handler(int sig) {
  if (sig == SIGINT)
    printf("\nIntrusion Detection Report:\n");
    // if SYN Flood Attack is possible
    if (syn_attack) {
      printf("SYN flood attack possible\n");
      printf("%d SYN packets detected from %d IP addresses in %f seconds\n",num_syn,num_syn_ip,time_syn);
    }
    // if SYN Flood Attack is not detected
    else {
      printf("No SYN flooding attack detected\n");
      printf("%d SYN packets detected from %d IP addresses in %f seconds\n",num_syn,num_syn_ip,time_syn);
    }
    // Number of ARP responses
    printf("%d ARP responses (cache poisoning)\n", arp_responses);

    // Number of URL Blacklist violations
    printf("%d URL Blacklist violations\n", url_violations);
    // quit
    exit(0);
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {
  // call signal handler
  signal(SIGINT, signal_handler);

  // Open network interface for packet capture
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture \n", interface);
  }
  // allocate memory for dynamic array
  source_ips = (unsigned long *) malloc(sizeof(unsigned long)*10);
  //arrival_times = (double *) malloc(sizeof(double)*10);

  // Capture packets (very ugly code)
  struct pcap_pkthdr header;
  const unsigned char *packet;
  while (1) {
    // Capture a  packet
    packet = pcap_next(pcap_handle, &header);
    if (packet == NULL) {
      // pcap_next can return null if no packet is seen within a timeout
      if (verbose) {
        printf("No packet received. %s\n", pcap_geterr(pcap_handle));
      }
    } else {
      // Optional: dump raw data to terminal
      if (verbose) {
        dump(packet, header.len);
      }
      // Dispatch packet for processing
      dispatch(&header, packet, verbose);
    }
  }
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
