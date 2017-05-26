#include "sniffer.h"

#define DEVICE_NAME "ens33" 

struct sockaddr_in src, dst;
struct ifreq ifr;

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
    struct ether_header * eth = (struct ether_header *)buffer;
    handleEthHdr(eth);

    void * netHdr = (void*)eth + sizeof(struct ether_header);
    if (ntohs(eth->ether_type) == ETH_P_IP)
    {
        struct ip * ip = (struct ip *)(buffer + sizeof(struct ether_header));
        handleIpHdr(ip);
        void * transHdr = (void*)ip + sizeof(struct iphdr);

        switch (ip->ip_p) 
        {
            case IPPROTO_ICMP:
                handleIcmpHdr((struct icmphdr *)transHdr);
                break;
            case IPPROTO_TCP:
                handleTcpHdr((struct tcphdr *)transHdr);
                break;
            case IPPROTO_UDP:
                handleUdpHdr((struct udphdr *)transHdr);
                break;
            default:
                break;
        }

    }
    else if (ntohs(eth->ether_type) == ETH_P_ARP)
    {
        handleArpHdr((struct arphdr *)netHdr);
    }
    else if (ntohs(eth->ether_type) == ETH_P_RARP)
    {

    }



}

void handleEthHdr(struct ether_header * eth)
{
    printf("%s --> %s\t", ether_ntoa((const struct ether_addr *)&eth->ether_shost), ether_ntoa((const struct ether_addr *)&eth->ether_dhost)); 
    switch(ntohs(eth->ether_type))
    {
        case ETH_P_IP:
            printf("[IP]\n");
            break;
        case ETH_P_ARP:
            printf("[ARP]\n");
            break;
        case ETH_P_RARP:
            printf("[RARP]\n");
            break;
        default:
            printf("\n");
            break;
    }
}

void handleIpHdr(struct ip * ip)
{
    printf("%s => %s\n", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
}

void handleIcmpHdr(struct icmphdr * icmp)
{

}

void handleTcpHdr(struct tcphdr * tcp)
{

}

void handleUdpHdr(struct udphdr * udp)
{

}
