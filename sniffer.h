#include <sys/socket.h>
#include <error.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <netdb.h>
#include <net/if.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>

void handlePacket(unsigned char *, int);
void handleEthHdr(struct ether_header *);
void handleIpHdr(struct ip *);
void handleIcmpHdr(struct icmp *);
void handleTcpHdr(struct tcphdr *);
void handleUdpHdr(struct udphdr *);
void handleArpHdr(struct arphdr *);
