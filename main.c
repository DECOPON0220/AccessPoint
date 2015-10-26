#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <pthread.h>
//----- RewritePacket()
#include <netinet/tcp.h>
#include <netinet/udp.h>
//-----
#include "mydef.h"
#include "mystruct.h"
#include "myprotocol.h"
#include "ifutil.h"
#include "netutil.h"
#include "checksum.h"
#include "debug.h"



// --- Global Variable ---
const char *NameDev1="wlan1";
const char *NameDev2="eth1";

int DebugOut=OFF;
int StatusFlag=STA_DISCOVER;
int EndFlag=OFF;

char hostMacAddr[SIZE_MAC];
char hostIpAddr[SIZE_IP];
char raspMacAddr[SIZE_MAC];
char raspIpAddr[SIZE_IP];
char dev1MacAddr[SIZE_MAC];
char dev2MacAddr[SIZE_MAC];
char *dev1IpAddr="192.168.30.1";    // 192.168.30.1
char dev2IpAddr[SIZE_IP];    // 192.168.20.~
char allocIpAddr[SIZE_IP];

DEVICE	Device[2];



int AnalyzePacket(int deviceNo,u_char *data,int size)
{
  struct ether_header *eh;
  eh=(struct ether_header *)data;

  if(size<sizeof(struct ether_header)){
    DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_header)\n",deviceNo,size);
    return(-1);
  }
  DebugPrintf("[%d]",deviceNo);
  if(DebugOut){
    PrintEtherHeader(eh,stderr);
  }
  
  // Check My Protocol
  if(StatusFlag==STA_DISCOVER) {
    if(chkMyProtocol(data, raspMacAddr, dev1MacAddr, raspIpAddr, dev1IpAddr, DISCOVER, size)==-1){
      StatusFlag=STA_APPROVAL;
      return(-1);
    }
  } else if (StatusFlag==STA_APPROVAL) {
    if(chkMyProtocol(data, raspMacAddr, dev1MacAddr, allocIpAddr, dev1IpAddr, APPROVAL, size)==-1){
      strcpy(raspIpAddr, allocIpAddr);
      StatusFlag=STA_WAIT;
      return(-1);
    }
  }

  return(0);
}

int RewritePacket (int deviceNo, u_char *data, int size) {
  u_char *ptr;
  struct ether_header *eh;
  int lest, len;
  
  ptr=data;
  lest=size;
  
  if(lest<sizeof(struct ether_header)){
    DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_header)\n",deviceNo,lest);
    return(-1);
  }

  eh=(struct ether_header *)ptr;
  ptr+=sizeof(struct ether_header);
  lest-=sizeof(struct ether_header);

  char dMACaddr[18];
  char sMACaddr[18];;

  // Get dMAC, sMAC
  my_ether_ntoa_r(eh->ether_dhost, dMACaddr, sizeof(dMACaddr));
  my_ether_ntoa_r(eh->ether_shost, sMACaddr, sizeof(sMACaddr));

  // wirelessNIC -> physicalNIC
  if(deviceNo==0){
    // Rewrite MAC Address
    my_ether_aton_r(dev2MacAddr, eh->ether_shost);
    if(strncmp(dMACaddr, dev1MacAddr, SIZE_MAC)==0){
      my_ether_aton_r(hostMacAddr, eh->ether_dhost);
    }
    
    // Case: IP
    if (ntohs(eh->ether_type)==ETHERTYPE_IP) {
      struct iphdr *iphdr;
      u_char option[1500];
      int optLen;
	
      iphdr=(struct iphdr *)ptr;
      ptr+=sizeof(struct iphdr);
      lest-=sizeof(struct iphdr);
      
      optLen=iphdr->ihl*4-sizeof(struct iphdr);
      
      if(optLen>0){
	memcpy(option, ptr, optLen);
	ptr+=optLen;
	lest-=optLen;
      }

      // Rewrite IP Address
      if(iphdr->saddr==inet_addr(raspIpAddr)){
	iphdr->saddr=inet_addr(dev2IpAddr);
      }
      if(iphdr->daddr==inet_addr(dev1IpAddr)){
	iphdr->daddr=inet_addr(hostIpAddr);
      }
      
      iphdr->check=0;
      iphdr->check=calcChecksum2((u_char *)iphdr, sizeof(struct iphdr), option, optLen);

      // Case : TCP
      if(iphdr->protocol==IPPROTO_TCP){
	struct tcphdr *tcphdr;
	
	len=ntohs(iphdr->tot_len)-iphdr->ihl*4;
	tcphdr=(struct tcphdr *)ptr;

	tcphdr->check=0;
	tcphdr->check=checkIPDATAchecksum(iphdr, ptr, len);
      }
      // Case : UDP
      if(iphdr->protocol==IPPROTO_UDP){
	struct udphdr* udphdr;
	
	len=ntohs(iphdr->tot_len)-iphdr->ihl*4;
	udphdr=(struct udphdr *)ptr;
	udphdr->check=0;
      }
    }
    // physicalNIC -> wirelessNIC
  } else if(deviceNo==1){
    // Rewrite MAC Address
    my_ether_aton_r(dev1MacAddr, eh->ether_shost);
    if(strncmp(dMACaddr, dev2MacAddr, SIZE_MAC)==0){
      my_ether_aton_r(raspMacAddr, eh->ether_dhost);
    }

    // Case: IP
    if (ntohs(eh->ether_type)==ETHERTYPE_IP) {
      struct iphdr *iphdr;
      u_char option[1500];
      int optLen;
	
      iphdr=(struct iphdr *)ptr;
      ptr+=sizeof(struct iphdr);
      lest-=sizeof(struct iphdr);
      
      optLen=iphdr->ihl*4-sizeof(struct iphdr);
      
      if(optLen>0){
	memcpy(option, ptr, optLen);
	ptr+=optLen;
	lest-=optLen;
      }
      
      // Rewrite IP Address
      if(iphdr->saddr==inet_addr(hostIpAddr)){
	iphdr->saddr=inet_addr(dev1IpAddr);
      }
      if(iphdr->daddr==inet_addr(dev2IpAddr)){
	iphdr->daddr=inet_addr(raspIpAddr);
      }
       
      iphdr->check=0;
      iphdr->check=calcChecksum2((u_char *)iphdr, sizeof(struct iphdr), option, optLen);

      // Case : TCP
      if(iphdr->protocol==IPPROTO_TCP){
	struct tcphdr *tcphdr;
	
	len=ntohs(iphdr->tot_len)-iphdr->ihl*4;
	tcphdr=(struct tcphdr *)ptr;

	tcphdr->check=0;
	tcphdr->check=checkIPDATAchecksum(iphdr, ptr, len);
      }
      // Case : UDP
      if(iphdr->protocol==IPPROTO_UDP){
	struct udphdr* udphdr;
	
	len=ntohs(iphdr->tot_len)-iphdr->ihl*4;
	udphdr=(struct udphdr *)ptr;
	udphdr->check=0;
      }
    }
  }
  return(0);
}

int sendMyProtocol()
{
  while(EndFlag==0){
    if(StatusFlag==2){
      printf("Send Offer Packet\n");
      
      strcpy(allocIpAddr, "192.168.30.11");
      create_myprotocol(Device[0].soc, dev1MacAddr, raspMacAddr, dev1IpAddr, allocIpAddr, OFFER);
      
      usleep(10000 * 100);
    }
  }
  return(0);
}

int Bridge()
{
  struct pollfd	targets[2];
  int	nready,i,size;
  u_char	buf[2048];

  // WLAN1
  targets[0].fd=Device[0].soc;
  targets[0].events=POLLIN|POLLERR;
  // ETH1
  targets[1].fd=Device[1].soc;
  targets[1].events=POLLIN|POLLERR;

  while(EndFlag==0){
    switch(nready=poll(targets,2,100)){
    case	-1:
      if(errno!=EINTR){
	perror("poll");
      }
      break;
    case	0:
      break;
    default:
      for(i=0;i<2;i++){
	if(targets[i].revents&(POLLIN|POLLERR)){
	  if((size=read(Device[i].soc,buf,sizeof(buf)))<=0){
	    perror("read");
	  }
	  else{
	    if(AnalyzePacket(i,buf,size)!=-1 && RewritePacket(i,buf,size)!=-1){
	      if((size=write(Device[(!i)].soc,buf,size))<=0){
		//perror("write");
	      }
	    }
	  }
	}
      }
      break;
    }
  }

  return(0);
}

int DisableIpForward()
{
  FILE    *fp;
  if((fp=fopen("/proc/sys/net/ipv4/ip_forward","w"))==NULL){
    DebugPrintf("cannot write /proc/sys/net/ipv4/ip_forward\n");
    return(-1);
  }
  fputs("0",fp);
  fclose(fp);

  return(0);
}

void EndSignal(int sig)
{
  EndFlag=ON;
}

void *thread1 (void *args) {
  DebugPrintf("Create Thread1\n");
  Bridge();
  return NULL;
}

void *thread2 (void *args) {
  DebugPrintf("Create Thread2\n");
  sendMyProtocol();
  return NULL;
}

int main(int argc,char *argv[],char *envp[])
{
  pthread_t th1,th2;
  
  getArpCache(NameDev2, hostMacAddr, hostIpAddr);
  
  // Init Wireless Interface IP Address
  if(chgIfIp(NameDev1, inet_addr(dev1IpAddr))==0){
    DebugPrintf("Change IP Address\n%s IP: %s\n", NameDev1, dev1IpAddr);
  }

  // Get IP and Mac Address
  getIfMac(NameDev1, dev1MacAddr);
  getIfMac(NameDev2, dev2MacAddr);
  getIfIp(NameDev2, dev2IpAddr);

  // Init Socket
  if((Device[0].soc=InitRawSocket(NameDev1,1,0))==-1){
    DebugPrintf("InitRawSocket:error:%s\n",NameDev1);
    return(-1);
  }
  DebugPrintf("%s OK\n",NameDev1);

  if((Device[1].soc=InitRawSocket(NameDev2,1,0))==-1){
    DebugPrintf("InitRawSocket:error:%s\n",NameDev2);
    return(-1);
  }
  DebugPrintf("%s OK\n",NameDev2);

  DisableIpForward();

  signal(SIGINT,EndSignal);
  signal(SIGTERM,EndSignal);
  signal(SIGQUIT,EndSignal);

  signal(SIGPIPE,SIG_IGN);
  signal(SIGTTIN,SIG_IGN);
  signal(SIGTTOU,SIG_IGN);

  DebugPrintf("bridge start\n");
  int status;
  if ((status = pthread_create(&th1, NULL, thread1, NULL)) != 0) {
    printf("pthread_create%s\n", strerror(status));
  }
  if ((status = pthread_create(&th2, NULL, thread2, NULL)) != 0) {
    printf("pthread_create%s\n", strerror(status));
  }
  DebugPrintf("bridge end\n");

  pthread_join(th1, NULL);
  pthread_join(th2, NULL);

  close(Device[0].soc);
  close(Device[1].soc);

  return(0);
}
