#include "analysis.h"
#include "dispatch.h"
#include "sniff.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include <netinet/in.h>
// global variables to be passed to sniff
bool syn_attack = false;
int num_syn = 0;
int num_syn_ip;
double time_syn = 0.0;
int arp_responses = 0;
int url_violations = 0;
unsigned long *source_ips;
// dynamic array variables
int size = 0;
int capacity = 10;
int ind = 0;

static double start_time = 0.0;
static double rate = 0.0;
static double unique = 0.0;

// function to return arrival time of packet
double get_time() {
  struct timeval begin;
  gettimeofday(&begin, NULL);
  double ret = (begin.tv_sec) + (begin.tv_usec)/1000000.0;
  return ret;
}
// pushes IP address into dynamic array
void pushIP(unsigned long value){
    // if resizing is needed, reallocate memory
    if (size>capacity) {
      unsigned long *tmp_ptr = (unsigned long *) realloc(source_ips, sizeof(unsigned long)*size*2);
      // error checking
      if (tmp_ptr != NULL) {
        source_ips = tmp_ptr; 
       //printf("reallocated ");
        capacity = size*2;
      }
      else {
        perror("Failed to reallocate memory.");
      }
    }

  pthread_mutex_lock(&muxlock); // ensure thread safety
  source_ips[ind] = value; // add IP address to next index in array
  pthread_mutex_unlock(&muxlock); 
  size = size+1; // increase size
}

// analyse runs each time a packet is intercepted
void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
  #define ETH_HLEN 14 // Total octets in ethernet header
  // parse ethernet header
  struct ether_header * eth_header = (struct ether_header *) packet;
  // store ethernet type
  unsigned short ethernet_type = ntohs(eth_header->ether_type);

  // if ethernet type is IP, then parse IP header
  if (ethernet_type == 0x0800) {
    struct ip * ip_hdr = (struct ip *)(packet + ETH_HLEN);
    // store ip header length, protocol and source ip address
    unsigned char headerlen = (ip_hdr->ip_hl)*4;
    unsigned char ip_protocol = (ip_hdr->ip_p);
    unsigned long sourceip = ntohl(ip_hdr->ip_src.s_addr);
    // check current ip is correct
    if (verbose) {
      printf("%lu current ip ",sourceip);
    }

    // if IP Protocol is TCP, then parse TCP header
    if (ip_protocol == 0x06) {
      struct tcphdr * tcp_hdr = (struct tcphdr *)(packet + ETH_HLEN + headerlen);
      // if it is TCP SYN packet
      if (tcp_hdr->syn == 1 && (tcp_hdr->fin == 0) && (tcp_hdr->rst == 0) && (tcp_hdr->psh == 0) && (tcp_hdr->ack == 0) && (tcp_hdr->urg == 0)) {
          // if first SYN packet received
          if (time_syn == 0.0) {
            start_time = get_time(); // store first arrival time
            //printf("%f = first arrival time ", arrival_times[0]);
          }   
          pthread_mutex_lock(&muxlock); // ensure thread safe operations
          num_syn++; // increment SYN packet counter
          pthread_mutex_unlock(&muxlock); 
        
          double current_time = get_time(); // store arrival time of current packet
          double elapsed_time = current_time - start_time; // calculate elapsed time
         
          pthread_mutex_lock(&muxlock); 
          time_syn = elapsed_time;// time_syn is most recent arrival time - first arrival time
          pthread_mutex_unlock(&muxlock);          
          
          // call methods to add source ip to dynamic array
          //pushArrival(current_time);
          pushIP(sourceip);

          // check if source ip is unique address
          bool unq = true;
          int i;
          for (i = 0; i < size-1; i++) 
            if (source_ips[i] == sourceip && (size != 1)) {
              // set flag to false
              unq=false;
              if (verbose) {
                printf("%lu stored ip \n",source_ips[i]);
                printf("%lu current ip\n",sourceip);
                printf("not unique\n");
              }
            } 
          // if unique source ip address
          if (unq) {
            pthread_mutex_lock(&muxlock);
            num_syn_ip++; // increment SYN unique packet counter
            pthread_mutex_unlock(&muxlock);
          }
          
          ind++; // increment arrival array index
          //ind2++; // increment ip array index
          rate = (num_syn_ip)/(elapsed_time); // calculate rate of SYN packets
          unique = (num_syn_ip/num_syn)*100; // calculate uniqueness of IP addresses

          // if rate is over 100 or uniqueness is >= 90, then SYN attack
          if (rate > 100 && unique >= 90) {
            pthread_mutex_lock(&muxlock);
            syn_attack = true; // set SYN to true
            pthread_mutex_unlock(&muxlock);
          }
          else {
            pthread_mutex_lock(&muxlock);
            syn_attack = false; // set SYN to false
            pthread_mutex_unlock(&muxlock);
          }
      }
      // store data offset, payload and destination port
      unsigned char data_offset = (tcp_hdr->th_off)*4;
      char * payload = (char *)(packet + ETH_HLEN + headerlen + data_offset);
      unsigned short tcp_destport = ntohs(tcp_hdr->th_dport);

      // if destination port 80
      if (tcp_destport == 80) {
        // search for blacklisted URL
        if (strstr(payload, "Host: www.telegraph.co.uk") != NULL) {
          pthread_mutex_lock(&muxlock);
          url_violations++; // increment url violations counter
          pthread_mutex_unlock(&muxlock);
        }
      }
    }
  } 
  // else if ethernet type is ARP, parse ARP Header
  else if (ethernet_type == 0x0806) {
    struct ether_arp * arp_hdr = (struct ether_arp *) (packet + ETH_HLEN);
    // store ARP opcode
    unsigned short arp_opc = ntohs(arp_hdr->arp_op);
    if (verbose) {
      printf("%hu opcode",arp_opc);
    }
    // if message type from opcode is any response
    if (arp_opc == 2 || arp_opc == 4 || arp_opc == 6 || arp_opc == 9) {
      pthread_mutex_lock(&muxlock);
      arp_responses++; // incremenent arp responses counter
      pthread_mutex_unlock(&muxlock);
    }
  }
}

