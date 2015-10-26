#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "mydef.h"
#include "netutil.h"



struct ifreq *getIfInfo(const char *device,struct ifreq *ifreq,int flavor)
{
  int fd;

  fd=socket(AF_INET,SOCK_DGRAM,0);
  memset(ifreq,'\0',sizeof(*ifreq));
  strcpy(ifreq->ifr_name,device);
  ioctl(fd,flavor,ifreq);
  close(fd);

  return(ifreq);
}

char *getIfMac(const char *device,char *macAddr)
{
  struct ifreq ifreq;
  u_char       tmpAddr[6];

  getIfInfo(device,&ifreq,SIOCGIFHWADDR);
  
  int i;
  for(i=0;i<6;i++) tmpAddr[i]=(char)ifreq.ifr_hwaddr.sa_data[i];
  my_ether_ntoa_r(tmpAddr,macAddr,SIZE_MAC);

  return(macAddr);
}

char *getIfIp(const char *device,char *ipAddr)
{
  struct ifreq ifreq;
  
  getIfInfo(device,&ifreq,SIOCGIFADDR);
  memcpy(ipAddr,inet_ntoa(((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr),SIZE_IP);

  return(ipAddr);
}

int chgIfIp(const char *device, u_int32_t ip)
{
  int                fd;
  struct ifreq       ifr;
  struct sockaddr_in *s_in;

  fd=socket(AF_INET,SOCK_DGRAM,0);

  s_in=(struct sockaddr_in *)&ifr.ifr_addr;
  s_in->sin_family=AF_INET;
  s_in->sin_addr.s_addr=ip;

  strncpy(ifr.ifr_name,device,IFNAMSIZ-1);

  if (ioctl(fd,SIOCSIFADDR,&ifr)!=0) {
    perror("ioctl");
  }

  close(fd);
  return(0);
}
