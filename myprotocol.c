#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "mydef.h"
#include "mystruct.h"
#include "netutil.h"
#include "ifutil.h"


// tmp
extern const char *NameDev1;
extern int StatusFlag;

void make_ethernet(struct ether_header *eth,unsigned char *ether_dhost,
		   unsigned char *ether_shost,u_int16_t ether_type)
{
  memcpy(eth->ether_dhost,ether_dhost,6);
  memcpy(eth->ether_shost,ether_shost,6);
  eth->ether_type=htons(ether_type);
}

void make_mydhcp(MYPROTO *myproto,char *sip,char *dip,u_short type)
{
  myproto->ip_src=inet_addr(sip);
  myproto->ip_dst=inet_addr(dip);
  myproto->type=htons(type);
}

void create_myprotocol(int soc,char *smac,char *dmac,char *sip,char *dip,u_short type)
{
  char   *sp;
  char   send_buff[MAXSIZE];
  u_char smac_addr[6];
  u_char dmac_addr[6];

  sp = send_buff + sizeof(struct ether_header);

  my_ether_aton_r(smac, smac_addr);
  my_ether_aton_r(dmac, dmac_addr);
  
  make_mydhcp((MYPROTO *) sp, sip, dip, type);
  make_ethernet((struct ether_header *) send_buff, dmac_addr, smac_addr, MYPROTOCOL);

  int len;
  len = sizeof(struct ether_header) + sizeof(MYPROTO);
  if (write(soc, send_buff, len) < 0) {
    perror("write");
  }
}

int chkMyProtocol(u_char *data, char *smac, char *dmac, char *sip, char *dip, u_short type, int size)
{
  u_char              *ptr;
  int                 lest;
  struct ether_header *eh;
  
  ptr=data;
  lest=size;
  
  eh=(struct ether_header *)ptr;
  ptr+=sizeof(struct ether_header);
  lest-=sizeof(struct ether_header);

  char sMACaddr[18];
  char dMACaddr[18];
  
  my_ether_ntoa_r(eh->ether_shost, sMACaddr, sizeof(sMACaddr));
  my_ether_ntoa_r(eh->ether_dhost, dMACaddr, sizeof(dMACaddr));

  // Check Ethernet header
  if((strncmp(dMACaddr, dmac, SIZE_MAC)==0) &&
     (ntohs(eh->ether_type)==MYPROTOCOL)){
    MYPROTO *myproto;
    
    myproto=(MYPROTO *) ptr;
    ptr+=sizeof(MYPROTO);
    lest-=sizeof(MYPROTO);
    
    // Check Myprotocol
    if(ntohs(myproto->type)==type &&
       (myproto->ip_src==inet_addr("00H.00H.00H.00H")) &&
       (myproto->ip_dst==inet_addr("FF.FF.FF.FFH"))){
      printf("Recieve Offer Packet\n");
      memcpy(smac, sMACaddr, sizeof(sMACaddr));
      return(-1);
    } else if(ntohs(myproto->type)==type &&
	      (strncmp(sMACaddr, smac, SIZE_MAC)==0) &&
	      (myproto->ip_src==inet_addr(sip)) &&
	      (myproto->ip_dst==inet_addr(dip))){
      printf("Receive Approval Packet\n");
      return(-1);
    }
  }

  return(0);
}
