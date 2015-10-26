#define MAXSIZE      8192
#define SIZE_MAC     18
#define SIZE_IP      15
#define ON           1
#define OFF          0
#define DISCOVER     0x1001
#define OFFER        0x1002
#define APPROVAL     0x1003
#define MYPROTOCOL   0x1010
#define STA_DISCOVER 1
#define STA_APPROVAL 2
#define STA_WAIT     3

// ARP CACHE
#define xstr(s) str(s)
#define str(s) #s
#define ARP_CACHE       "/proc/net/arp"
#define ARP_STRING_LEN  1023
#define ARP_BUFFER_LEN  (ARP_STRING_LEN + 1)
#define ARP_LINE_FORMAT "%" xstr(ARP_STRING_LEN) "s %*s %*s " \
                        "%" xstr(ARP_STRING_LEN) "s %*s " \
                        "%" xstr(ARP_STRING_LEN) "s"
