u_int16_t calcChecksum(u_char *data,int len);
u_int16_t calcChecksum2(u_char *data1,int len1,u_char *data2,int len2);
unsigned short  checkIPchecksum(struct iphdr *iphdr,u_char *option,int optionLen);
int checkIPDATAchecksum(struct iphdr *iphdr,unsigned char *data,int len);
unsigned short udpchecksum(struct iphdr *ip, struct udphdr *udp);
