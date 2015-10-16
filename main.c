#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<poll.h>
#include	<errno.h>
#include	<signal.h>
#include	<stdarg.h>
#include	<sys/socket.h>
#include	<arpa/inet.h>
#include	<netinet/if_ether.h>
#include	"netutil.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "myprotocol.h"
#include "checksum.h"

#define MAXSIZE 8192
#define SIZE_MAC 18
#define SIZE_IP 15

const char *NameDev1="wlan1";
const char *NameDev2="eth1";
char *IpWirelessIf="192.168.30.1";
char *nextRouterIp="192.168.20.1";


typedef struct	{
  int	soc;
}DEVICE;
DEVICE	Device[2];

int StatusFlag=1;
int DebugFlag=0;
int EndFlag=0;

char cliMacAddr[SIZE_MAC];
char dev1MacAddr[SIZE_MAC];
char dev2MacAddr[SIZE_MAC];
char dev1IpAddr[SIZE_IP];
char dev2IpAddr[SIZE_IP];

int DebugPrintf(char *fmt,...)
{
  if(DebugFlag){
    va_list	args;

    va_start(args,fmt);
    vfprintf(stderr,fmt,args);
    va_end(args);
  }

  return(0);
}

int DebugPerror(char *msg)
{
  if(DebugFlag){
    fprintf(stderr,"%s : %s\n",msg,strerror(errno));
  }

  return(0);
}

/*
void MakeIPAddress (char *ip)
{
  char first[]="192";
  char second[]="168";
  char third[]="30";
  char fourth[]="11";
  
  strncpy(ip, first, sizeof(first));
  strcat(ip, ".");
  strcat(ip, second);
  strcat(ip, ".");
  strcat(ip, third);
  strcat(ip, ".");
  strcat(ip, fourth);
}
*/

void make_ethernet(struct ether_header *eth, unsigned char *ether_dhost,
		   unsigned char *ether_shost, u_int16_t ether_type) {
  memcpy(eth->ether_dhost, ether_dhost, 6);
  memcpy(eth->ether_shost, ether_shost, 6);
  eth->ether_type = htons(ether_type);
}

void make_mydhcp(struct myprotocol *myproto, char *sip, char *dip, u_short type) {
  myproto->ip_src = inet_addr(sip);
  myproto->ip_dst = inet_addr(dip);
  myproto->type = htons(type);
}

void create_myprotocol (int soc, char *smac, char *dmac, char *sip, char *dip, u_short type) {
  char *sp;
  char send_buff[MAXSIZE];
  u_char smac_addr[6];
  u_char dmac_addr[6];

  sp = send_buff + sizeof(struct ether_header);

  my_ether_aton_r(smac, smac_addr);
  my_ether_aton_r(dmac, dmac_addr);
  
  make_mydhcp((struct myprotocol *) sp, sip, dip, type);
  make_ethernet((struct ether_header *) send_buff, dmac_addr, smac_addr, type);

  int len;
  len = sizeof(struct ether_header) + sizeof(struct myprotocol);
  if (write(soc, send_buff, len) < 0) {
    perror("write");
  }
}

int sendMyProtocol(int deviceNo)
{
  while(EndFlag==0){
    if(StatusFlag==2){
      printf("Send Offer Packet\n");
      
      char *dip = "192.168.30.11";
      create_myprotocol(Device[deviceNo].soc, dev1MacAddr, cliMacAddr, IpWirelessIf, dip, OFFER);
      
      usleep(10000 * 100);
    }
  }
    
  return(0);
}

int AnalyzePacket(int deviceNo,u_char *data,int size)
{
  u_char	*ptr;
  int	lest;
  struct ether_header	*eh;

  ptr=data;
  lest=size;

  if(lest<sizeof(struct ether_header)){
    DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_header)\n",deviceNo,lest);
    return(-1);
  }

  eh=(struct ether_header *)ptr;
  ptr+=sizeof(struct ether_header);
  lest-=sizeof(struct ether_header);

  DebugPrintf("[%d]",deviceNo);
  if(DebugFlag){
    PrintEtherHeader(eh,stderr);
  }
  
  // Check My Protocol
  if(StatusFlag==1) {
    char sMACaddr[18];
    char dMACaddr[18];

    my_ether_ntoa_r(eh->ether_shost, sMACaddr, sizeof(sMACaddr));
    my_ether_ntoa_r(eh->ether_dhost, dMACaddr, sizeof(dMACaddr));
    memcpy(cliMacAddr, sMACaddr, sizeof(sMACaddr));
    
    if(strncmp(dMACaddr, "ff:ff:ff:ff:ff:ff", SIZE_MAC)==0 &&
       ntohs(eh->ether_type)==DISCOVER){
      struct myprotocol *myproto;
      
      printf("-----\nRecieve Discover Packet\n");
      myproto=(struct myprotocol *) ptr;
      ptr+=sizeof(struct myprotocol);
      lest-=sizeof(struct myprotocol);

      if((myproto->ip_src==inet_addr("00H.00H.00H.00H")) &&
	 (myproto->ip_dst==inet_addr("FF.FF.FF.FFH")) &&
	 (ntohs(myproto->type)==DISCOVER)){
	StatusFlag=2;
	return(-1);
      }
    }
  } else if (StatusFlag==2) {
      char sMACaddr[18];
      char dMACaddr[18];

      my_ether_ntoa_r(eh->ether_shost, sMACaddr, sizeof(sMACaddr));
      my_ether_ntoa_r(eh->ether_dhost, dMACaddr, sizeof(dMACaddr));
      
      if(strncmp(dMACaddr, dev1MacAddr, SIZE_MAC)==0 &&
	 strncmp(sMACaddr, cliMacAddr, SIZE_MAC)==0 &&
	 ntohs(eh->ether_type)==APPROVAL){
	struct myprotocol *myproto;
	
	printf("Recieve Approval Packet\n");
	myproto=(struct myprotocol *) ptr;
	ptr+=sizeof(struct myprotocol);
	lest-=sizeof(struct myprotocol);
	
	if((myproto->ip_src==inet_addr("192.168.30.11")) &&
	   (myproto->ip_dst==inet_addr("192.168.30.1")) &&
	   (ntohs(myproto->type)==APPROVAL)){
	  printf("Finish Assign IP\n-----\n");
	  StatusFlag=1;
	  return(-1);
	}
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

  // wirelessNIC -> physicalNIC
  if(deviceNo==0){
    char dMACaddr[18];
    char sMACaddr[18];
    u_char tmpMACaddr[6];

    // Get dMAC, sMAC
    my_ether_ntoa_r(eh->ether_dhost, dMACaddr, sizeof(dMACaddr));
    my_ether_ntoa_r(eh->ether_shost, sMACaddr, sizeof(sMACaddr));
    
    // shost = physicalNIC IP
    int i;
    my_ether_aton_r(dev2MacAddr, tmpMACaddr);
    for(i=0;i<6;i++) eh->ether_shost[i]=tmpMACaddr[i];

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
      
      // Rewrite MAC Address
      char *dmac="dc:fb:02:aa:64:fa";
      my_ether_aton_r(dev2MacAddr, eh->ether_shost);
      my_ether_aton_r(dmac, eh->ether_dhost);
      // Rewrite IP Address
      if(iphdr->saddr==inet_addr("192.168.30.11")){
	iphdr->saddr=inet_addr(dev2IpAddr);
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

    // physicalNIC -> wirelessNIC
  if(deviceNo==1){
    char dMACaddr[18];
    char sMACaddr[18];
    u_char tmpMACaddr[6];

    // Get dMAC, sMAC
    my_ether_ntoa_r(eh->ether_dhost, dMACaddr, sizeof(dMACaddr));
    my_ether_ntoa_r(eh->ether_shost, sMACaddr, sizeof(sMACaddr));
    
    // dhost = client MAC
    int i;
    my_ether_aton_r(cliMacAddr, tmpMACaddr);
    for(i=0;i<6;i++) eh->ether_shost[i]=tmpMACaddr[i];

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
      
      // Rewrite MAC Address
      //my_ether_aton_r(dev2MacAddr, eh->ether_shost);
      char *dmac="cc:e1:d5:15:d6:25";
      my_ether_aton_r(dmac, eh->ether_dhost);
      // Rewrite IP Address
       if(iphdr->daddr==inet_addr("192.168.20.14")){
	iphdr->daddr=inet_addr("192.168.30.11");
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

int Bridge()
{
  struct pollfd	targets[2];
  int	nready,i,size;
  u_char	buf[9192];


  targets[0].fd=Device[0].soc;
  targets[0].events=POLLIN|POLLERR;
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
  EndFlag=1;
}

void getIfInfo (const char *device, struct ifreq *ifreq, int flavor)
{
  int fd;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  memset(ifreq, '\0', sizeof(*ifreq));
  strcpy(ifreq->ifr_name, device);
  ioctl(fd, flavor, ifreq);
  close(fd);
}

void getIfMac (const char *device, char *macAddr)
{
  struct ifreq ifreq;
  u_char tmpAddr[6];

  getIfInfo(device, &ifreq, SIOCGIFHWADDR);
  
  int i;
  for(i=0;i<6;i++) tmpAddr[i]=(char)ifreq.ifr_hwaddr.sa_data[i];
  my_ether_ntoa_r(tmpAddr, macAddr, SIZE_MAC);
}

void getIfIp (const char *device, char *ipAddr)
{
  struct ifreq ifreq;
  
  getIfInfo(device, &ifreq, SIOCGIFADDR);
  memcpy(ipAddr, inet_ntoa(((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr), SIZE_IP);
}

void *thread1 (void *args) {
  printf("Create Thread1\n");
  Bridge();
  return NULL;
}

void *thread2 (void *args) {
  printf("Create Thread2\n");
  sendMyProtocol(0);
  return NULL;
}

int changeIPAddr(const char *device, u_int32_t ip)
{
  int fd;
  struct ifreq ifr;
  struct sockaddr_in *s_in;

  fd=socket(AF_INET, SOCK_DGRAM, 0);
  
  s_in=(struct sockaddr_in *)&ifr.ifr_addr;
  s_in->sin_family = AF_INET;
  s_in->sin_addr.s_addr = ip;

  strncpy(ifr.ifr_name, device, IFNAMSIZ-1);
  
  if (ioctl(fd, SIOCSIFADDR, &ifr) != 0) {
    perror("ioctl");
  }

  close(fd);
  return(0);
}


int main(int argc,char *argv[],char *envp[])
{
  pthread_t th1,th2;
  
  // Config Wireless Device IP Address
  if(changeIPAddr(NameDev1, inet_addr(IpWirelessIf))==0){
    printf("Change IP Address\n%s IP: %s\n", NameDev1, IpWirelessIf);
  }

  // Get IP and Mac Address
  getIfMac(NameDev1, dev1MacAddr);
  getIfIp(NameDev1, dev1IpAddr);
  getIfMac(NameDev2, dev2MacAddr);
  getIfIp(NameDev2, dev2IpAddr);

  // Init Soc
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
