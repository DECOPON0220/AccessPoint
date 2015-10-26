#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include "mydef.h"

extern int	DebugPrintf(char *fmt,...);
extern int	DebugPerror(char *msg);



int InitRawSocket(const char *device,int promiscFlag,int ipOnly)
{
  struct ifreq	ifreq;
  struct sockaddr_ll	sa;
  int	soc;

  if(ipOnly){
    if((soc=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP)))<0){
      DebugPerror("socket");
      return(-1);
    }
  }
  else{
    if((soc=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
      DebugPerror("socket");
      return(-1);
    }
  }

  memset(&ifreq,0,sizeof(struct ifreq));
  strncpy(ifreq.ifr_name,device,sizeof(ifreq.ifr_name)-1);
  if(ioctl(soc,SIOCGIFINDEX,&ifreq)<0){
    DebugPerror("ioctl");
    close(soc);
    return(-1);
  }
  sa.sll_family=PF_PACKET;
  if(ipOnly){
    sa.sll_protocol=htons(ETH_P_IP);
  }
  else{
    sa.sll_protocol=htons(ETH_P_ALL);
  }
  sa.sll_ifindex=ifreq.ifr_ifindex;
  if(bind(soc,(struct sockaddr *)&sa,sizeof(sa))<0){
    DebugPerror("bind");
    close(soc);
    return(-1);
  }

  if(promiscFlag){
    if(ioctl(soc,SIOCGIFFLAGS,&ifreq)<0){
      DebugPerror("ioctl");
      close(soc);
      return(-1);
    }
    ifreq.ifr_flags=ifreq.ifr_flags|IFF_PROMISC;
    if(ioctl(soc,SIOCSIFFLAGS,&ifreq)<0){
      DebugPerror("ioctl");
      close(soc);
      return(-1);
    }
  }

  return(soc);
}

char *my_ether_ntoa_r(u_char *hwaddr,char *buf,socklen_t size)
{
  snprintf(buf,size,"%02x:%02x:%02x:%02x:%02x:%02x",
	   hwaddr[0],hwaddr[1],hwaddr[2],hwaddr[3],hwaddr[4],hwaddr[5]);

  return(buf);
}

u_char *my_ether_aton_r(char *hwaddr, u_char *buf)
{
  sscanf(hwaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	 &buf[0], &buf[1], &buf[2], &buf[3], &buf[4], &buf[5]);

  return(buf);
}

int getArpCache()
{
  FILE *arpCache=fopen(ARP_CACHE,"r");
  if(!arpCache){
    perror("Arp Cache: Failed to open file \"" ARP_CACHE "\"");
    return (0);
  }
  
  // Ignore the first line, which contains the header
  char header[ARP_BUFFER_LEN];
  if(!fgets(header,sizeof(header),arpCache)){
    return(0);
  }

  char ipAddr[ARP_BUFFER_LEN], hwAddr[ARP_BUFFER_LEN], device[ARP_BUFFER_LEN];
  int count=0;
  while(3==fscanf(arpCache,ARP_LINE_FORMAT,ipAddr,hwAddr,device)){
    printf("%03d: Mac Address of [%s] on [%s] is \"%s\"\n",
	   ++count,ipAddr,device,hwAddr);
  }
  fclose(arpCache);
  return(0);
}

int PrintEtherHeader(struct ether_header *eh,FILE *fp)
{
  char	buf[80];

  fprintf(fp,"ether_header----------------------------\n");
  fprintf(fp,"ether_dhost=%s\n",my_ether_ntoa_r(eh->ether_dhost,buf,sizeof(buf)));
  fprintf(fp,"ether_shost=%s\n",my_ether_ntoa_r(eh->ether_shost,buf,sizeof(buf)));
  fprintf(fp,"ether_type=%02X",ntohs(eh->ether_type));
  switch(ntohs(eh->ether_type)){
  case	ETH_P_IP:
    fprintf(fp,"(IP)\n");
    break;
  case	ETH_P_IPV6:
    fprintf(fp,"(IPv6)\n");
    break;
  case	ETH_P_ARP:
    fprintf(fp,"(ARP)\n");
    break;
  default:
    fprintf(fp,"(unknown)\n");
    break;
  }

  return(0);
}

