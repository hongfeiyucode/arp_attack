//arp_struct.h 数据定义头文件
#define HRD_TYPE    0x0001          //硬件类型：Ethernet网接口类型为1
#define PRO_TYPE    0x0800          //协议类型：IP协议类型为0x0800
#define EH_TYPE     0x0806          //Ethernet网类型
#define ARP_REQUEST 0x0001          //arp请求
#define ARP_REPLY   0x0002          //arp应答
#define MAC_LEN     6               //MAC地址长度
#define IP_LEN      4               //IP地址长度
#pragma pack(push,1)                //设置让结构体以一个字节对齐
struct ethernet_head {               //Ethernet网头部，长度为14B
	unsigned char dest_mac[6];        //目标主机Mac地址
	unsigned char source_mac[6];    //源端MAC地址
	unsigned short eh_type;         //Ethernet网类型
};
struct arp_head {                    //Arp头部，长度为46B
	unsigned short hardware_type;   //硬件类型：Ethernet网接口类型为1
	unsigned short protocol_type;   //协议类型：IP协议类型为0x0800
	unsigned char add_len;          //硬件地址长度：MAC地址长度为6B
	unsigned char pro_len;          //协议地址长度：IP地址长度为4B
	unsigned short option;          //操作：Arp请求为1，Arp应答为2
	unsigned char sour_addr[6];     //源MAC地址，发送方的MAC地址
	unsigned long sour_ip;          //源IP地址，发送方的IP地址
	unsigned char dest_addr[6];     //目的MAC，ARP请求中没有意义，响应中为接收方MAC
	unsigned long dest_ip;          //目的IP，ARP请求中为请求解析的IP，ARP响应中为接收方IP
	unsigned char padding[18];      //填充数据，这里全为0
};
typedef struct arp_packet {
	struct ethernet_head eth;       //Ethernet网头部
	struct arp_head arp;            //ARP数据帧头部
}Arp_Packet;
#pragma pack(pop)
//该函数用来填充arp数据帧
void enArpReqPack(Arp_Packet *arp,   //指向arp结构体的指针
	char *chLocalMac,                //源MAC地址
	char *chLocalIp,                 //源IP地址
	char *chDstMac,                  //目的MAC地址
	char *chDstIp,                   //目的IP地址
	bool is_request);                //是否是请求包，为真则为请求包，为假则为应答包
									 //该函数用来将字符串MAC地址转换成16进制MAC地址。
bool GetMacAddr(unsigned char *chsMac, unsigned char *chdMac);
//该函数用来将字符型数据转换成实际数据
unsigned char charToData(const char ch);
