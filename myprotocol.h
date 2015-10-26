void make_ethernet(struct ether_header *eth,unsigned char *ether_dhost,
		   unsigned char *ether_shost,u_int16_t ether_type);
void make_mydhcp(MYPROTO *myproto,char *sip,char *dip,u_short type);
void create_myprotocol(int soc,char *smac,char *dmac,char *sip,char *dip,u_short type);
int chkMyProtocol(u_char *data, char *smac, char *dmac, char *sip, char *dip, u_short type, int size);
