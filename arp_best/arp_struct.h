//arp_struct.h ���ݶ���ͷ�ļ�
#define HRD_TYPE    0x0001          //Ӳ�����ͣ�Ethernet���ӿ�����Ϊ1
#define PRO_TYPE    0x0800          //Э�����ͣ�IPЭ������Ϊ0x0800
#define EH_TYPE     0x0806          //Ethernet������
#define ARP_REQUEST 0x0001          //arp����
#define ARP_REPLY   0x0002          //arpӦ��
#define MAC_LEN     6               //MAC��ַ����
#define IP_LEN      4               //IP��ַ����
#pragma pack(push,1)                //�����ýṹ����һ���ֽڶ���
struct ethernet_head {               //Ethernet��ͷ��������Ϊ14B
	unsigned char dest_mac[6];        //Ŀ������Mac��ַ
	unsigned char source_mac[6];    //Դ��MAC��ַ
	unsigned short eh_type;         //Ethernet������
};
struct arp_head {                    //Arpͷ��������Ϊ46B
	unsigned short hardware_type;   //Ӳ�����ͣ�Ethernet���ӿ�����Ϊ1
	unsigned short protocol_type;   //Э�����ͣ�IPЭ������Ϊ0x0800
	unsigned char add_len;          //Ӳ����ַ���ȣ�MAC��ַ����Ϊ6B
	unsigned char pro_len;          //Э���ַ���ȣ�IP��ַ����Ϊ4B
	unsigned short option;          //������Arp����Ϊ1��ArpӦ��Ϊ2
	unsigned char sour_addr[6];     //ԴMAC��ַ�����ͷ���MAC��ַ
	unsigned long sour_ip;          //ԴIP��ַ�����ͷ���IP��ַ
	unsigned char dest_addr[6];     //Ŀ��MAC��ARP������û�����壬��Ӧ��Ϊ���շ�MAC
	unsigned long dest_ip;          //Ŀ��IP��ARP������Ϊ���������IP��ARP��Ӧ��Ϊ���շ�IP
	unsigned char padding[18];      //������ݣ�����ȫΪ0
};
typedef struct arp_packet {
	struct ethernet_head eth;       //Ethernet��ͷ��
	struct arp_head arp;            //ARP����֡ͷ��
}Arp_Packet;
#pragma pack(pop)
//�ú����������arp����֡
void enArpReqPack(Arp_Packet *arp,   //ָ��arp�ṹ���ָ��
	char *chLocalMac,                //ԴMAC��ַ
	char *chLocalIp,                 //ԴIP��ַ
	char *chDstMac,                  //Ŀ��MAC��ַ
	char *chDstIp,                   //Ŀ��IP��ַ
	bool is_request);                //�Ƿ����������Ϊ����Ϊ�������Ϊ����ΪӦ���
									 //�ú����������ַ���MAC��ַת����16����MAC��ַ��
bool GetMacAddr(unsigned char *chsMac, unsigned char *chdMac);
//�ú����������ַ�������ת����ʵ������
unsigned char charToData(const char ch);
