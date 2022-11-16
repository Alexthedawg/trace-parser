/* Note (take this out before final submission):
 * format of the c++ program -
 * 1. include libraries
 * 2. define constants
 * 3. extern variables
 * 4. function declaration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <cstring>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "next.h"

/* constants */
#define OPTSTR "t:slpm"
#define UTOD   pow(10, USECS_LEN)

/* optarg is the argument following an element */
extern char *optarg;

/* function declarations below */
void usage();
void trace(int sflag, int lflag, int pflag, int mflag);
void smode(int fd);
void lmode(int fd);
void pmode(int fd);
void mmode(int fd);
void errexit(char *msg);
unsigned short next_packet(int fd, struct pkt_info *pinfo);

/* global variables */
std::string trace_file;

/* MAIN */
int main(int argc, char **argv) {
  /* argument counters */
  int opt;
  int tflag = 0;
  int sflag = 0;
  int lflag = 0;
  int pflag = 0;
  int mflag = 0;
  
  /* parsing arguments */
  while ((opt = getopt(argc, argv, OPTSTR)) != EOF) {
    switch (opt) {
      case 't':
        trace_file = optarg;
        tflag++;
        break;
      case 's':
        ++sflag;
        break;
      case 'l':
        ++lflag;
        break;
      case 'p':
        ++pflag;
        break;
      case 'm':
        ++mflag;
        break;
      default:
        printf("Invalid argument\n");
        usage();
        return EXIT_FAILURE;
    }
  }

  /* validating arguments */
  /* the t option must be called once */
  if (tflag != 1) {
    usage();
    return EXIT_FAILURE;
  }
  /* only one other option must be called */
  if (sflag + lflag + pflag + mflag != 1) {
    usage();
    return EXIT_FAILURE;
  }

  /* start packet trace */
  trace(sflag, lflag, pflag, mflag);

  return EXIT_SUCCESS;
}

/* defines the usage for this program */
void usage() {
  printf("./proj4 -t trace_file -s|-l|-p|-m\n");
}

/* initiates packet trace process */
void trace(int sflag, int lflag, int pflag, int mflag) {
  FILE *file;
  file = fopen(&trace_file[0], "r");
  int fd = fileno(file);
  /*TODO implement modes */
  if (sflag) {
    smode(fd);
  }/* else if (lflag) {
    lmode();
  } else if (pflag) {
    pmode();
  } else if (mflag) {
    mmode();
  }*/
}

/* runs program in s mode*/
void smode(int fd) {
  struct pkt_info *pinfo;
  pinfo = (struct pkt_info *) malloc(sizeof (*pinfo));
  double first_time = -1;
  double final_time = -1;
  int numpkts = 0;
  int numips = 0;
  
  while (next_packet(fd, pinfo) == 1) {
    if (first_time == -1)
      first_time = pinfo->now;
    final_time = pinfo->now;
    if (pinfo->ethh->ether_type == ETHERTYPE_IP &&
        pinfo->caplen > sizeof (struct ether_header))
      numips++;
    numpkts++;
  } 
  free(pinfo);
  
  fprintf(stdout, "FIRST PKT: %0.6f\n", first_time);
  fprintf(stdout, "LAST PKT: %0.6f\n", final_time);
  fprintf(stdout, "TOTAL PACKETS: %d\n", numpkts);
  fprintf(stdout, "IP PACKETS: %d\n", numips);
}

/* runs program in s mode*/

/* runs program in s mode*/

/* runs program in s mode*/


/* error message function for next_packet */
void errexit(char *msg) {
    fprintf (stdout,"%s\n",msg);
    exit (1);
}

/* fd - an open file to read packets from
   pinfo - allocated memory to put packet info into for one packet

   returns:
   1 - a packet was read and pinfo is setup for processing the packet
   0 - we have hit the end of the file and no packet is available
 */
unsigned short next_packet(int fd, struct pkt_info *pinfo) {
    struct meta_info meta;
    int bytes_read;

    memset (pinfo,0x0,sizeof (struct pkt_info));
    memset (&meta,0x0,sizeof (struct meta_info));

    /* read the meta information */
    bytes_read = read (fd,&meta,sizeof (meta));
    if (bytes_read == 0)
        return (0);
    if (bytes_read < (int) sizeof (meta))
        errexit ((char *) "cannot read meta information");
    pinfo->caplen = ntohs (meta.caplen);
    /* set pinfo->now based on meta.secs & meta.usecs */
    pinfo->now = ntohl (meta.secs);
    pinfo->now += ((double) ntohl (meta.usecs)) / (double) (UTOD);
    if (pinfo->caplen == 0)
        return (1);
    if (pinfo->caplen > MAX_PKT_SIZE)
        errexit ((char *) "packet too big");
    /* read the packet contents */
    bytes_read = read (fd,pinfo->pkt,pinfo->caplen);
    if (bytes_read < 0)
        errexit ((char *) "error reading packet");
    if (bytes_read < pinfo->caplen)
        errexit ((char *) "unexpected end of file encountered");
    if (bytes_read < (int) sizeof (struct ether_header))
        return (1);
    pinfo->ethh = (struct ether_header *)pinfo->pkt;
    pinfo->ethh->ether_type = ntohs (pinfo->ethh->ether_type);
    if (pinfo->ethh->ether_type != ETHERTYPE_IP)
        /* nothing more to do with non-IP packets */
        return (1);
    if (pinfo->caplen == sizeof (struct ether_header))
        /* we don't have anything beyond the ethernet header to process */
        return (1);
    /* set pinfo->iph to start of IP header */
    pinfo->iph = (struct iphdr *) (pinfo->pkt + ETHER_HDR_LEN);
    pinfo->iph->protocol = ntohs (pinfo->iph->protocol);
    /* if TCP packet,
          set pinfo->tcph to the start of the TCP header
          setup values in pinfo->tcph, as needed */
    if (pinfo->iph->protocol == IPPROTO_TCP)
        pinfo->tcph = (struct tcphdr *) (pinfo->iph + ntohs (pinfo->iph->tot_len));
    /* if UDP packet,
          set pinfo->udph to the start of the UDP header,
          setup values in pinfo->udph, as needed */
    if (pinfo->iph->protocol == IPPROTO_UDP)
        pinfo->udph = (struct udphdr *) (pinfo->iph + ntohs (pinfo->iph->tot_len));
    return (1);
}
