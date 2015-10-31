#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include "mydef.h"
#include "netutil.h"
#include "device.h"



extern int	DebugPrintf(char *fmt,...);
extern int	DebugPerror(char *msg);

void Device_init(Device *this, const char *name)
{
  strcpy(this->name, name);
  func_setSocket(this);
  func_setMacAddr(this);
  func_setIpAddr(this);
}

void Device_setIpAddr(Device *this, char *ipaddr)
{
  strncpy(this->ipaddr, ipaddr, SIZE_IP);
  func_confIpAddr(this->name, ipaddr);
}

char *Device_getName(Device *this)
{
  return this->name;
}

int  Device_getSoc(Device *this)
{
  return this->soc;
}

char *Device_getIpAddr(Device *this)
{
  return this->ipaddr;
}

char *Device_getMacAddr(Device *this)
{
  return this->macaddr;
}

void Device_printInfo(Device *this)
{
  printf("Mac Address of [%s] on [%s] is \"%s\"\n",
	 this->ipaddr, this->name, this->macaddr);
}

void Device_del(Device *this)
{
  close(this->soc);
}

void func_setSocket(Device *this)
{
  struct ifreq	     ifreq;
  struct sockaddr_ll sa;
  int	             soc;

  if((soc=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
    DebugPerror("socket");
    return;
  }

  memset(&ifreq,0,sizeof(struct ifreq));
  strncpy(ifreq.ifr_name,this->name,sizeof(ifreq.ifr_name)-1);
  if(ioctl(soc,SIOCGIFINDEX,&ifreq)<0){
    DebugPerror("ioctl");
    close(soc);
    return;
  }
  sa.sll_family=PF_PACKET;
  sa.sll_protocol=htons(ETH_P_ALL);
  sa.sll_ifindex=ifreq.ifr_ifindex;
  if(bind(soc,(struct sockaddr *)&sa,sizeof(sa))<0){
    DebugPerror("bind");
    close(soc);
    return;
  }

  if(ioctl(soc,SIOCGIFFLAGS,&ifreq)<0){
    DebugPerror("ioctl");
    close(soc);
    return;
  }
  ifreq.ifr_flags=ifreq.ifr_flags|IFF_PROMISC;
  if(ioctl(soc,SIOCSIFFLAGS,&ifreq)<0){
    DebugPerror("ioctl");
    close(soc);
    return;
  }

  this->soc=soc;
}

void func_setMacAddr(Device *this)
{
  struct ifreq ifreq;
  u_char       tmpAddr[6];

  func_getDeviceInfo(this->name,&ifreq,SIOCGIFHWADDR);
  
  int i;
  for(i=0;i<6;i++) tmpAddr[i]=(char)ifreq.ifr_hwaddr.sa_data[i];
  my_ether_ntoa_r(tmpAddr,this->macaddr,SIZE_MAC);
}

void func_setIpAddr(Device *this)
{
  struct ifreq ifreq;
  
  func_getDeviceInfo(this->name,&ifreq,SIOCGIFADDR);
  memcpy(this->ipaddr,inet_ntoa(((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr),SIZE_IP);
}

void func_confIpAddr(char *name, char *ip)
{
  int                fd;
  struct ifreq       ifr;
  struct sockaddr_in *s_in;

  fd=socket(AF_INET,SOCK_DGRAM,0);

  s_in=(struct sockaddr_in *)&ifr.ifr_addr;
  s_in->sin_family=AF_INET;
  s_in->sin_addr.s_addr=inet_addr(ip);

  strncpy(ifr.ifr_name,name,IFNAMSIZ-1);

  if (ioctl(fd,SIOCSIFADDR,&ifr)!=0) {
    perror("ioctl");
  }

  close(fd);
}

struct ifreq *func_getDeviceInfo(char *name, struct ifreq *ifreq, int flavor)
{
  int fd;

  fd=socket(AF_INET,SOCK_DGRAM,0);
  memset(ifreq,'\0',sizeof(*ifreq));
  strcpy(ifreq->ifr_name,name);
  ioctl(fd,flavor,ifreq);
  close(fd);

  return(ifreq);
}
