#include "sniffer.h"

#define DEVICE_NAME "ens33" 

struct sockaddr_in src, dst;
struct ifreq ifr;
int sockraw;
FILE* file = NULL;

void help()
{
    puts("sudo ./sniffer [log_file]");
}

void printTime()
{
    static char timeBuffer[255];
    time_t t = time(0);
    strftime(timeBuffer, 255, "%F %T\t", localtime(&t));
    printf("\033[4;34m%s\033[0m ", timeBuffer);
}

/* Get host name from IPV4 address */
void printHostName(const struct in_addr in)
{
    struct hostent * he = gethostbyaddr((char *)&in, sizeof(struct in_addr), AF_INET);
    if (!he)
    {
        printf("%s", inet_ntoa(in));
    }
    else
    {
        printf("%s", he->h_name);
    }
}

void cleanup(int sig)
{
    printf("\033[0m\nStore into file...\n");
    fclose(file);
    close(sockraw);
    exit(0);
}


void dumpIntoFile(FILE* file, const char *buffer, int size)
{
    if (!file) return;
    for (int i = 0; i < size; i += 16)
    {
        fprintf(file, "%010x | ", i);
        for (int j = 0; j < 16; ++j)
        {
            fprintf(file, "%02x ", *(u_char *)(buffer + i + j));
        }
        fprintf(file, " | ");
        for (int j = 0; j < 16; ++j)
        {
            if (isprint(*(buffer + i + j)))
            {
                fprintf(file, "%c", *(buffer + i + j));
            }
            else
            {
                fprintf(file, ".");
            }
        }
        fprintf(file, "\n");
    }
    fprintf(file, "\n\n");

    fflush(file);

}

int main(int argc, char * argv[])
{
    if (argc > 2)
    {
        help();
    }
    else if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
    {
        help();
    }
    else
    {
        file = fopen(argv[1], "a");
        if (!file)
        {
            perror("File open error!");
        }
    }


    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    signal(SIGKILL, cleanup);
    signal(SIGQUIT, cleanup);

    /* Set raw socker mode */
    sockraw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
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

    /* Enable promisc mode on NIC */
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


    return 0;
}

void handlePacket(unsigned char * buffer, int size)
{
    fflush(stdout);
    printTime();
    struct ether_header * eth = (struct ether_header *)buffer;
    // handleEthHdr(eth);

    void * netHdr = (void*)eth + sizeof(struct ether_header);
    if (ntohs(eth->ether_type) == ETH_P_IP)
    {
        struct ip * ip = (struct ip *)(buffer + sizeof(struct ether_header));
        handleIpHdr(ip);
        void * transHdr = (void*)ip + sizeof(struct iphdr);

        switch (ip->ip_p) 
        {
            case IPPROTO_ICMP:
                handleIcmpHdr((struct icmp *)transHdr);
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
        /*handleArpHdr((struct arphdr *)netHdr);*/
    }
    else if (ntohs(eth->ether_type) == ETH_P_RARP)
    {

    }

    dumpIntoFile(file, buffer, size);

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
    printf("\033[32m");
    // printf("%s => %s\t", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
    printHostName(ip->ip_src);
    printf("(%s)", inet_ntoa(ip->ip_src));
    printf(" => ");
    printHostName(ip->ip_dst);
    printf("(%s)", inet_ntoa(ip->ip_dst));
    printf(" \033[0m");
    switch (ip->ip_p)
    {
        case IPPROTO_TCP:
            printf("[TCP]\n");
            break;
        case IPPROTO_UDP:
            printf("[UDP]\n");
            break;
        case IPPROTO_ICMP:
            printf("[ICMP]\n");
            break;
        default:
            printf("\n");
            break;
    }
    printf("(tos %x, ttl %d, id %d, offset %d, flags ",
            ip->ip_tos, ip->ip_ttl, ntohs(ip->ip_id), ntohs(ip->ip_off) & IP_OFFMASK);
    if (ntohs(ip->ip_off) & IP_RF)
    {
        printf("[RF]");
    }
    else if (ntohs(ip->ip_off) & IP_DF)
    {
        printf("[DF]");
    }
    else if (ntohs(ip->ip_off) & IP_MF)
    {
        printf("[MF]");
    }
    printf(", proto %d, length %d)\n", ip->ip_p, ntohs(ip->ip_len));
}

void handleIcmpHdr(struct icmp * icmp)
{
    printf("type %u code %u\n", icmp->icmp_type, icmp->icmp_code);
}

void handleTcpHdr(struct tcphdr * tcp)
{
    printf("\033[35m");
    printf("%d -> %d ", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
    printf("\033[0m");
    if (tcp->th_flags & TH_FIN) printf("FIN ");
    if (tcp->th_flags & TH_SYN) printf("SYN ");
    if (tcp->th_flags & TH_RST) printf("RST ");
    if (tcp->th_flags & TH_PUSH) printf("PUSH ");
    if (tcp->th_flags & TH_ACK) printf("ACK ");
    if (tcp->th_flags & TH_URG) printf("URG ");
    printf("seq %u ack %u ", ntohs(tcp->th_seq), ntohs(tcp->th_ack)); 
    printf("win %u ", ntohs(tcp->th_win));
    if (tcp->th_flags & TH_URG) printf("urp %u ", ntohs(tcp->th_urp));
    printf("\n");
}

void handleUdpHdr(struct udphdr * udp)
{
    printf("\033[35m%d -> %d\033[0m len %u\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport), udp->uh_ulen);
}

