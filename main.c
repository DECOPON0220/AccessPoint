#include <stdio.h>
//----- func_getAddAddr()
#include <stdlib.h>
//-----
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
#include "device.h"



// --- Global Variable ---
Device  device1;
Device  device2;
Device *device[]={&device1, &device2};
int     EndFlag=OFF;
int     DebugOut=OFF;
int     InitApFlag=OFF;

// --- Constant ----------
const char *NAME_DEV1="wlan1";    // AP
const char *NAME_DEV2="eth1";     // Connect Server

int StatusFlag=STA_DISCOVER;

char serverMacAddr[SIZE_MAC];
char serverIpAddr[SIZE_IP];
char raspMacAddr[SIZE_MAC];
char raspIpAddr[SIZE_IP];



char *func_getAddAddr(char *ipaddr, int addNum)
{
  int lenIp, f_octet;
  
  lenIp=strlen(ipaddr);
  ipaddr+=lenIp-1;
  f_octet=atoi(ipaddr);
  f_octet+=addNum;
  sprintf(ipaddr,"%d",f_octet);
  ipaddr-=lenIp-1;

  return(ipaddr);
}

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

    char dMacAddr[SIZE_MAC];
    char sMacAddr[SIZE_MAC];

    switch(ntohs(myproto->type)){
    case   INITAP:;
      my_ether_ntoa_r(eh->ether_dhost, dMacAddr, sizeof(dMacAddr));

      if(strncmp(Device_getMacAddr(device[1]), dMacAddr, SIZE_MAC)==0){
	printf("--- Receive Build AP Packet ---\n");
	my_ether_ntoa_r(eh->ether_shost, sMacAddr, sizeof(sMacAddr));
	
	// Configure IP Address of AP
	Device_setIpAddr(device[0], inet_ntoa(*(struct in_addr *)&myproto->ip_dst));
	
	// Configure IP Address of Server Side Dev
	char tmpIp[SIZE_IP];
	strncpy(tmpIp, Device_getIpAddr(device[0]), SIZE_IP);
	func_getAddAddr(tmpIp, 1);
	Device_setIpAddr(device[1], tmpIp);
	
	// (Debug): Print Device Information
	printf("--- Build Access Point---------\n");
	Device_printInfo(device[0]);
	Device_printInfo(device[1]);

	// Finish Configure AP
	InitApFlag=ON;
      }
      break;
      /*
    case   DISCOVER:;
      char *dip="FF:FF:FF:FF";
      char *sip="00H.00H.00H.00H";
      char disc_dMacAddr[18];
      my_ether_ntoa_r(eh->ether_dhost, disc_dMacAddr, sizeof(disc_dMacAddr));

      if((strncmp(disc_dMacAddr, dev1MacAddr, SIZE_MAC)==0) &&
	 (myproto->ip_src==inet_addr(sip)) &&
	 (myproto->ip_dst==inet_addr(dip))){
	printf("--- Bridge Discover Packet ---\n");
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
	printf("--- Bridge Offer Packet --------\n");
	
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
	printf("--- Bridge Approval Packet ---\n");

	// Rewrite Packet
	my_ether_aton_r(serverMacAddr, eh->ether_dhost);
	myproto->ip_dst=inet_addr(serverIpAddr);
      }
      */
    default:
      break;
    }
  }
  
  return(0);
}

int sendMyProtocol()
{
  char *CHK_MAC="ff:ff:ff:ff:ff:ff";
  char *CHK_SIP="00H.00H.00H.00H";
  char *CHK_DIP="FF.FF.FF.FF";

  while(EndFlag==0){
    if(InitApFlag==OFF){
      printf("--- Send Init AP Packet -------\n");
      
      create_myprotocol(Device_getSoc(device[1]),
			Device_getMacAddr(device[1]), CHK_MAC,
			CHK_SIP, CHK_DIP,
			INITAP);

      usleep(10000*100);
    }
  }
  return(0);
}

int Bridge()
{
  struct pollfd	targets[2];
  int	        nready,i,size;
  u_char	buf[2048];

  // "wlan1"
  targets[0].fd=Device_getSoc(device[0]);
  targets[0].events=POLLIN|POLLERR;
  // "eth1"
  targets[1].fd=Device_getSoc(device[1]);;
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
	  if((size=read(Device_getSoc(device[i]),buf,sizeof(buf)))<=0){
	    perror("read");
	  }
	  else{
	    if(AnalyzePacket(i,buf,size)!=-1){
	      if((size=write(Device_getSoc(device[!i]),buf,size))<=0){
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

  // Initialize
  Device_init(device[0], NAME_DEV1);
  Device_init(device[1], NAME_DEV2);

  // Print Device Information
  //Device_printInfo(device[0]);
  //Device_printInfo(device[1]);

  // Disable IPv4 IP Forward
  DisableIpForward();

  // Signal Handler
  signal(SIGINT,EndSignal);
  signal(SIGTERM,EndSignal);
  signal(SIGQUIT,EndSignal);
  signal(SIGPIPE,SIG_IGN);
  signal(SIGTTIN,SIG_IGN);
  signal(SIGTTOU,SIG_IGN);

  // Start Thread
  int status;
  if ((status = pthread_create(&th1, NULL, thread1, NULL)) != 0) {
    printf("pthread_create%s\n", strerror(status));
  }
  if ((status = pthread_create(&th2, NULL, thread2, NULL)) != 0) {
    printf("pthread_create%s\n", strerror(status));
  }
  pthread_join(th1, NULL);
  pthread_join(th2, NULL);

  Device_del(device[0]);
  Device_del(device[1]);

  return(0);
}
