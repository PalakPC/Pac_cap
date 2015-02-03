/*C program to capture packets and list the number of packets sent to and received from an IP address.*/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <time.h>

char ** data;
int count = 0;
int cdata[50];

char **allocate2D(int rows, int columns);

int main(int argc, char **argv) {
   int i, s, c, tcount1, f = 0, fd = fileno(stdin), tcount = 0;
   char *dev, errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* descr;
   u_char *ptr;
   fd_set fdset;
   time_t endtime;
   const u_char *packet;
   struct pcap_pkthdr hdr;
   struct ether_header *eptr;
   struct timeval tv = {0,0};
   extern char *optarg;
   extern int optind;
   while((c = getopt(argc, argv, "t:c:")) != -1) {
      switch(c) {
         case 't':  endtime = time(NULL) + atoi(optarg);
                    f = 1;
                    break;
         case 'c':  tcount1 = atoi(optarg);
                    f = 2;
                    break;
      }
   }
   data = allocate2D(50, 30);
   dev = pcap_lookupdev(errbuf);
   if(dev == NULL) {
      printf("%s\n", errbuf);
      exit(1);
   }
   descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
   if(descr == NULL) {
      printf("pcap_open_live(): %s\n", errbuf);
      exit(1);
   }
   sleep(5);
   do {
      int j;
      struct ip *ip;
      struct tcphdr *tcp;
      char *src = inet_ntoa(ip->ip_src);
      sleep(1);
      FD_ZERO(&fdset);
      FD_SET(fd, &fdset);
      packet = pcap_next(descr, &hdr);
      ip = (struct ip*) (packet + sizeof(struct ether_header));
      tcp = (struct tcphdr*) (packet + sizeof(struct ether_header) + sizeof(struct ip));
      data[count] = src;
      cdata[count] = 1;
      tcount++;
      if(count != 0) {
         for(j = 0; j < count; ++j) {
            if(data[count] == data[j]) {
               count--;
               cdata[j]++;
            }
         }
      }	
      count++;
      if((f == 1 && time(NULL) >= endtime) || (f == 2 && tcount >= tcount1))
         break;
   } while((s = select(fd+1, &fdset, NULL, NULL, &tv)) == 0);	
   printf("******************************************************************");
   printf("\nIP Address\tPacket Count\n");
   for(i = 0; i < count; ++i)
      printf("%s\t%d\n", data[i], cdata[i]);
   printf("******************************************************************\n");
   return 0;
}

char **allocate2D(int rows, int cols) {
   char **arr2D;
   int *i;
   i = (int *) malloc(sizeof(int));
   arr2D = (char**) malloc((rows) * sizeof(char*));
   for((*i) = 0; (*i) < (rows); (*i)++) 
      arr2D[*i] = (char*) malloc((cols) * sizeof(char));
   return arr2D;
}
