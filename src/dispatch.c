#include "dispatch.h"
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

#include "analysis.h"

// initialise single mutex lock, defined by default constructor
pthread_mutex_t muxlock = PTHREAD_MUTEX_INITIALIZER;

// create struct for analyse's arguments
struct analyse_args { struct pcap_pkthdr* header; const unsigned char* packet; int verbose; };

// function that will be ran multiple times simultaneously by threads
void *thread_code(void *arg) {
	// store the value arg passed to the thread
	struct analyse_args * args = (struct analyse_args *) arg;
	// run analyse function with arguments
    analyse(args->header, args->packet, args->verbose);
    //printf("\nThread code being executed\n");
    free(arg);
    return NULL;
}

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
	// create single thread
  pthread_t thread;
  // store size of analyse_args struct
  unsigned long size = sizeof(struct analyse_args);
  // allocate memory to the struct
	struct analyse_args * args = malloc(size);

	if (verbose) {
		printf("\nthread mem allocated\n");
	}
	// assign values in the struct
  args->header = header;
  args->packet = packet;
  args->verbose = verbose;
  // check for thread error
  int err = pthread_create(&thread, NULL, &thread_code, (void *) args);
  if (err != 0) {
  	printf("Cannot create thread: %s",strerror(err));
  }
  else if (verbose==1){
  	printf("Created thread successfully");
	}

 	//rejoin threads
 	pthread_join(thread, NULL);

}
