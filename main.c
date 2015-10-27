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
int InitApFlag=OFF;
int StatusFlag=STA_DISCOVER;
int EndFlag=OFF;

char serverMacAddr[SIZE_MAC];
char serverIpAddr[SIZE_IP];
char raspMacAddr[SIZE_MAC];
char raspIpAddr[SIZE_IP];
char dev1MacAddr[SIZE_MAC];
char dev2MacAddr[SIZE_MAC];
char dev1IpAddr[SIZE_IP];
char dev2IpAddr[SIZE_IP];

DEVICE	Device[2];



int AnalyzePacket(int deviceNo,u_char *data,int size)
{
  u_char *ptr;
  int lest;
  struct ether_header *eh;
  
  ptr=data;
  lest=size;
  if(size<sizeof(struct ether_header)){
    DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_header)\n",deviceNo,size);
    return(-1);
  }
  eh=(struct ether_header *)ptr;
  ptr+=sizeof(struct ether_header);
  lest-=sizeof(struct ether_header);
  DebugPrintf("[%d]",deviceNo);
  if(DebugOut){
    PrintEtherHeader(eh,stderr);
  }

  if(ntohs(eh->ether_type)==MYPROTOCOL){
    MYPROTO *myproto;
    myproto=(MYPROTO *)ptr;
    ptr+=sizeof(MYPROTO);
    lest-=sizeof(MYPROTO);

    switch(ntohs(myproto->type)){
    case   INITAP:;
      char init_dMacAddr[18];
      my_ether_ntoa_r(eh->ether_dhost, init_dMacAddr, sizeof(init_dMacAddr));

      if(strncmp(dev2MacAddr, init_dMacAddr, SIZE_MAC)==0){
	printf("Receive InitAP Packet\n");
	my_ether_ntoa_r(eh->ether_shost, serverMacAddr, sizeof(serverMacAddr));
	memcpy(dev1IpAddr, inet_ntoa(*(struct in_addr *)&myproto->ip_dst), SIZE_IP);
	//-----
	//memcpy(dev2IpAddr, "192.168.30.2", SIZE_IP);
	//-----
	memcpy(serverIpAddr, inet_ntoa(*(struct in_addr *)&myproto->ip_src), SIZE_IP);

	if(chgIfIp(NameDev1, inet_addr(dev1IpAddr))==0 &&
	   chgIfIp(NameDev2, inet_addr(dev2IpAddr))==0){
	  printf("Success change AP Address");
	  InitApFlag=ON;
	  
	  return(-1);
	}
      }
      break;
    case   DISCOVER:;
      char *dip="FF:FF:FF:FF";
      char *sip="00H.00H.00H.00H";
      char disc_dMacAddr[18];
      my_ether_ntoa_r(eh->ether_dhost, disc_dMacAddr, sizeof(disc_dMacAddr));

      if((strncmp(disc_dMacAddr, dev1MacAddr, SIZE_MAC)==0) &&
	 (myproto->ip_src==inet_addr(sip)) &&
	 (myproto->ip_dst==inet_addr(dip))){
	printf("Recive Discover Packet\n");
	my_ether_ntoa_r(eh->ether_shost, raspMacAddr, sizeof(raspMacAddr));
	
	// Rewrite Packet
	my_ether_aton_r(serverMacAddr, eh->ether_dhost);
      }
      break;
    case   OFFER:;
      char offr_dMacAddr[18];
      char offr_sMacAddr[18];
      my_ether_ntoa_r(eh->ether_dhost, offr_dMacAddr, sizeof(offr_dMacAddr));
      my_ether_ntoa_r(eh->ether_shost, offr_sMacAddr, sizeof(offr_sMacAddr));

      if((strncmp(offr_sMacAddr, serverMacAddr, SIZE_MAC)==0) &&
	 (strncmp(offr_dMacAddr, raspMacAddr, SIZE_MAC)==0) &&
	 (myproto->ip_src==inet_addr(serverIpAddr))){
	printf("Recive Offer Packet\n");
	
	// Rewrite Packet
	my_ether_aton_r(dev1MacAddr, eh->ether_shost);
	myproto->ip_src=inet_addr(dev1IpAddr);
      }
      break;
    case   APPROVAL:;
      char app_dMacAddr[18];
      char app_sMacAddr[18];
      my_ether_ntoa_r(eh->ether_dhost, app_dMacAddr, sizeof(app_dMacAddr));
      my_ether_ntoa_r(eh->ether_shost, app_sMacAddr, sizeof(app_sMacAddr));

      if((strncmp(app_sMacAddr, raspMacAddr, SIZE_MAC)==0) &&
	 (strncmp(app_dMacAddr, dev1MacAddr, SIZE_MAC)==0) &&
	 (myproto->ip_dst==inet_addr(dev1IpAddr))){
	printf("Recive APPROVAL Packet\n");

	// Rewrite Packet
	my_ether_aton_r(serverMacAddr, eh->ether_dhost);
	myproto->ip_dst=inet_addr(serverIpAddr);
      }
    default:
      break;
    }
  }
  
  return(0);
}

int sendMyProtocol()
{
  while(EndFlag==0){
    if(InitApFlag==OFF){
      printf("Send InitAP Packet\n");
      char *dmac="ff:ff:ff:ff:ff:ff";
      char *sip="00H.00H.00H.00H";
      char *dip="FF.FF.FF.FF";
      
      create_myprotocol(Device[1].soc, dev2MacAddr, dmac, sip, dip, INITAP);

      usleep(10000*100);
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
	    if(AnalyzePacket(i,buf,size)!=-1){
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
  
  getArpCache();

  // Get IP and Mac Address
  getIfMac(NameDev1, dev1MacAddr);
  getIfMac(NameDev2, dev2MacAddr);

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
