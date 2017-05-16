#include <sys/socket.h>
#include <error.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEVICE_NAME "ens33" 

struct sockaddr_in src, dst;
struct ifreq ifr;

void handlePacket(unsigned char *, int);

int main(int argc, char * argv[])
{
    int sockraw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    struct sockaddr saddr;
    int saddr_size, data_size;

    unsigned char * buffer = (unsigned char *)malloc(65536);
    memset(&ifr, 0, sizeof(struct ifreq));

    strcpy(ifr.ifr_name, DEVICE_NAME);

    if (ioctl(sockraw, SIOCGIFFLAGS, &ifr) == -1)
    {
        perror("Error: Could not retrieve flags from the device.\n");
        exit(1);
    }

    ifr.ifr_flags |= IFF_PROMISC;

    if (ioctl(sockraw, SIOCSIFFLAGS, &ifr) == -1)
    {
        perror("Error: Could not set the flags PROMISC.\n");
        exit(1);
    }

    if (ioctl(sockraw, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("Error: Could not getting the device index\n");
        exit(1);
    }

    setsockopt(sockraw, SOL_SOCKET, SO_BINDTODEVICE, DEVICE_NAME, strlen(DEVICE_NAME));
    if (sockraw < 0)
    {
        perror("Socket Error");
        return 1;
    }

    while(1)
    {
        saddr_size = sizeof(saddr);

        data_size = recvfrom(sockraw, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_size);

        if (data_size < 0)
        {
            printf("Recv Error");
            return 1;
        }

        handlePacket(buffer, data_size);
    }

    close(sockraw);

    return 0;
}

void handlePacket(unsigned char * buffer, int size)
{
    struct iphdr * ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    printf("%d", ip->protocol);
}
