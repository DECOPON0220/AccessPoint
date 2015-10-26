char *my_ether_ntoa_r(u_char *hwaddr,char *buf,socklen_t size);
u_char *my_ether_aton_r(char *hwaddr, u_char *buf);
int getArpCache();
int PrintEtherHeader(struct ether_header *eh,FILE *fp);
int InitRawSocket(const char *device,int promiscFlag,int ipOnly);
