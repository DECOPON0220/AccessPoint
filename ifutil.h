struct ifreq *getIfInfo(const char *device,struct ifreq *ifreq,int flavor);
char *getIfMac(const char *device,char *macAddr);
char *getIfIp(const char *device,char *ipAddr);
int chgIfIp(const char *device,u_int32_t ip);
