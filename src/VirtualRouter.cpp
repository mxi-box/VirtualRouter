// VirtualRouter.cpp: 定义控制台应用程序的入口点。
//

//#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "stdafx.h"
//#include "fileapi.h"
#include "winsock2.h"
#include "ws2tcpip.h"

#include "iostream"

#include "tap-windows.h"
#include "vr_packet.h"
#include "vr_route.h"

using std::cin;
using std::cout;
using std::endl;
using std::string;
using std::wstring;

DWORD pumpError(const char *process, DWORD errId) {
	cout << process << " ERROR:"<< errId << endl;
	cin.ignore(1, '\n');
	return errId;
}

byte IoControlBuffer[128];
BOOL sendDeviceIoControl(HANDLE h, DWORD code, LPVOID in, DWORD len) {
	DWORD returnLen;
	return DeviceIoControl(
		h,
		code,
		in,
		len,
		IoControlBuffer,
		128,
		&returnLen,
		NULL
	);
	for (size_t i = 0; i < returnLen; i++)
		cout << (DWORD32)(IoControlBuffer[i]) << ' ';
	cout << endl;
}

BOOL sendIntegerDeviceIoControl(HANDLE h, DWORD code, int in) {
	return sendDeviceIoControl(h, code, &in, sizeof(int));
}

BOOL sendBoolDeviceIoControl(HANDLE h, DWORD code, bool in) {
	return sendDeviceIoControl(h, code, &in, sizeof(bool));
}

BOOL sendByteDeviceIoControl(HANDLE h, DWORD code, const byte *in, DWORD len) {
	return sendDeviceIoControl(h, code, (LPVOID)in, len);
}


#define STRING_BUFFER_LENGTH 128
const string netCfgId = "{FEB44FA0-24A4-46E5-A060-9DB277E80065}";
const string path = USERMODEDEVICEDIR + netCfgId + TAP_WIN_SUFFIX;
const byte ip[] = { 10, 1, 1, 2, 10, 1, 1, 0, 255, 255, 255, 0 };
const byte dhcp_masq[] = { 10, 1, 1, 2, 255, 255, 255, 0, 10, 1, 1, 1, 255, 255, 255, 255};
const byte opt[] = { 6, 8, 8, 8, 8, 8, 8, 8, 4, 4 };

HANDLE fwpEngine;
WSADATA wsaData;
OVERLAPPED adapterReadOverlap, adapterWriteOverlap;
HANDLE adapter;
byte adapterBuffer[MTU];
DWORD error, adapterDataLength;
NATManager natman;

char stringBuffer[STRING_BUFFER_LENGTH];
void adapterPacketIncoming();
void socketPacketIncoming(GatewaySession &sess);

int main()
{	
	std::ios::sync_with_stdio(false);
	std::srand(std::time(0));

	//error = FwpmEngineOpen(
	//	NULL,
	//	RPC_C_AUTHN_DEFAULT,
	//	NULL,
	//	&fwpSession,
	//	&fwpEngine
	//);
	//if (error) {
	//	pumpError("Open WFP", error);
	//	return 1;
	//}

	//error = FwpmTransactionBegin(fwpEngine, 0);
	//if (error) {
	//	pumpError("Begin Transaction", error);
	//	return 1;
	//}

	//error = FwpmProviderAdd(fwpEngine, &fwpProvider, NULL);
	//if (error && error != FWP_E_ALREADY_EXISTS) {
	//	pumpError("Add Provider", error);
	//	return 1;
	//}

	//error = FwpmSubLayerAdd(fwpEngine, &fwpSublayer, NULL);
	//if (error && error != FWP_E_ALREADY_EXISTS) {
	//	pumpError("Add Sublayer", error);
	//	return 1;
	//}

	//
	//error = FwpmTransactionCommit(fwpEngine);
	//if (error) {
	//	pumpError("Commit Transaction", error);
	//	return 1;
	//}
	//Initialize virtual adapter
	adapter = CreateFileA(
		path.c_str(),
		//"\\\\.\\Global\\DummyPlug",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
		NULL
	);

	if (adapter == INVALID_HANDLE_VALUE) {
		pumpError("Open adapter", GetLastError());
		return 1;
	}
	//Initialize WSA
	if (error = WSAStartup(MAKEWORD(2, 2), &wsaData)) {
		pumpError("Initialize WSA", error);
		return 1;
	}

	//char hostname[128];
	//if(gethostname(hostname, 128)) {
	//	pumpError(GetLastError());
	//	return 1;
	//}


	//cout << hostname << endl;
	//hostent *host = gethostbyname(hostname);
	//for (int i = 0; host->h_addr_list[i] != NULL; i++) {
	//	in_addr addr = *(in_addr*)host->h_addr_list[i];
	//	inet_ntop(AF_INET, &addr, hostname, 128);
	//	cout << hostname << endl;
	//}
	//Configure TUNTAP
	if (sendByteDeviceIoControl(adapter, TAP_WIN_IOCTL_CONFIG_TUN, ip, 12))
		cout << "Done" << endl;
	else
		pumpError("Setup TUN", GetLastError());

	if (sendByteDeviceIoControl(adapter, TAP_WIN_IOCTL_CONFIG_DHCP_MASQ, dhcp_masq, 16))
		cout << "Done" << endl;
	else
		pumpError("Setup TUN DHCP", GetLastError());

	if (sendByteDeviceIoControl(adapter, TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT, opt, 10))
		cout << "Done" << endl;
	else
		pumpError("Setup TUN DHCP", GetLastError());
	
	if (sendIntegerDeviceIoControl(adapter, TAP_WIN_IOCTL_SET_MEDIA_STATUS, TRUE))
		cout << "Done" << endl;
	else
		pumpError("Setup TUN Media Status", GetLastError());

	adapterReadOverlap.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	adapterWriteOverlap.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	Sleep(1000);
	PTRGTWS gate_hk = natman.registerGateway("103.118.40.202");
	PTRGTWS gate_la = natman.registerGateway("38.143.2.153");
	if (error = natman.setup()) {
		pumpError("Setup NatManager", error);
		return 1;
	}
	//if (error = natman.addRoute("85.190.159.15", gate_la)) {
	//	pumpError("Add route", error);
	//	return 1;
	//}
	if (error = natman.addRoute("46.4.244.164", gate_hk)) {
		pumpError("Add route", error);
		return 1;
	}

	DWORD handleNum = natman.gatewaySessionNum() + 1;
	HANDLE *handles = new HANDLE[handleNum]{ adapterReadOverlap.hEvent };
	vector<PTRGTWS> GatewayMap;
	size_t ii = 0;
	for (PTRGTWS tGate = natman.gatewaySessionBegin(); tGate != natman.gatewaySessionEnd(); tGate++) {
		*(handles + ii + 1) = tGate->getRecvEvent();
		GatewayMap.push_back(tGate);
		ii++;
	}
	while (ReadFile(adapter, adapterBuffer, MTU, &adapterDataLength, &adapterReadOverlap)) {
		adapterPacketIncoming();
	}
	error = GetLastError();
	if (error != ERROR_IO_PENDING) {
		pumpError("First read from adapter", error);
		return 1;
	}

	for (PTRGTWS gate = natman.gatewaySessionBegin(); gate != natman.gatewaySessionEnd(); gate++) {
		while (gate->socketReadAsync()) {
			socketPacketIncoming(*gate);
		}
		error = GetLastError();
		if (error != ERROR_IO_PENDING) {
			pumpError("First read from socket", error);
			return 1;
		}
	}

	while (true) {
		DWORD stat = WaitForMultipleObjects(handleNum, handles, FALSE, INFINITE);
		DWORD index = stat - WAIT_OBJECT_0;
		if (index == 0) {
			do {
				if (!GetOverlappedResult(adapter, &adapterReadOverlap, &adapterDataLength, FALSE)) {
					pumpError("Get adapter read result", GetLastError());
					return 1;
				}
				adapterPacketIncoming();
			} while (ReadFile(adapter, adapterBuffer, MTU, &adapterDataLength, &adapterReadOverlap));
			error = GetLastError();
			if (error != ERROR_IO_PENDING) {
				pumpError("Read adapter", error);
				return 1;
			}
		} else {
			GatewaySession &sess = *GatewayMap[index - 1];
			do {
				if (!sess.getSocketReadResult()) {
					pumpError("Get socket result", GetLastError());
					return 1;
				}
				socketPacketIncoming(sess);
			} while (sess.socketReadAsync());
			error = GetLastError();
			if (error != ERROR_IO_PENDING) {
				pumpError("Read socket", error);
				return 1;
			}
		}
	}
	cin.ignore(1, '\n');
	//natman.~NATManager();
	CloseHandle(adapter);
	WSACleanup();
    return 0;
}

void adapterPacketIncoming() {
	IPV4_PACKET *ipv4;
	byte *buf = adapterBuffer;
	DWORD &len = adapterDataLength;

	if (isIPv4(buf)) {
		ipv4 = (IPV4_PACKET*)buf;
		PTRNATS nats;
		IPv4Point src, dest;
		DWORD rs;
		UDP_PACKET *udp;
		TCP_PACKET *tcp;
		switch (ipv4->protocol) {
		case IPPROTO_UDP:
			udp = (UDP_PACKET*)ipv4->payload();
			//cout << "send" << endl;
			//cout << udp->payloadLength() << endl;
			//cout << std::hex;
			//for (int i = 0; i < udp->payloadLength(); i++) {
			//	cout << (unsigned short)udp->payload[i] << ' ';
			//}
			//cout << std::dec << endl;
	
			src = IPv4Point(IPPROTO_UDP, ipv4->src, udp->srcPort), dest = IPv4Point(IPPROTO_UDP, ipv4->dest, udp->destPort);
			if (natman.getSessionByDestApp(dest, src, &nats)) {
				inet_ntop(AF_INET, &dest.addr, stringBuffer, STRING_BUFFER_LENGTH);
				cout << "Undefined destination " << stringBuffer << ':' << ntohs(dest.port) << endl;
				break;
			}
			//nats->refresh();
			ipv4->src = nats->routerLocal.addr;
			ipv4->dest = nats->next.addr;
			udp->srcPort = nats->routerLocal.port;
			udp->destPort = nats->next.port;
			ipv4->computeChecksum();
			udp->computeChecksum(ipv4->getFakeHeaderSum());

			if(rs = nats->route->socketWriteSync(ipv4, len)) {
				pumpError("write socket UDP", rs);
			}
			break;
		case IPPROTO_TCP:
			tcp = (TCP_PACKET*)ipv4->payload();
			unsigned short payloadLen = tcp->payloadLength(ipv4->payloadLength());
			cout << "send" << endl;
			cout << payloadLen << endl;
			src = IPv4Point(IPPROTO_TCP, ipv4->src, tcp->srcPort), dest = IPv4Point(IPPROTO_TCP, ipv4->dest, tcp->destPort);
			if (natman.getSessionByDestApp(dest, src, &nats)) {
				inet_ntop(AF_INET, &dest.addr, stringBuffer, STRING_BUFFER_LENGTH);
				cout << "Undefined destination " << stringBuffer << ':' << ntohs(dest.port) << endl;
				break;
			}
			//nats->refresh();
			ipv4->src = nats->routerLocal.addr;
			ipv4->dest = nats->next.addr;
			tcp->srcPort = nats->routerLocal.port;
			tcp->destPort = nats->next.port;
			ipv4->computeChecksum();
			tcp->computeChecksum(ipv4->getFakeHeaderSum(), ipv4->payloadLength());

			if (rs = nats->route->socketWriteSync(ipv4, len)) {
				pumpError("write socket TCP", rs);
			}
			break;
		}
	}
}

void socketPacketIncoming(GatewaySession &sess) {
	IPV4_PACKET *ipv4;
	byte *buf = sess.recvBuffer;
	DWORD &len = sess.dataRecv;;

	if (isIPv4(buf)) {
		ipv4 = (IPV4_PACKET*)buf;
		PTRNATS nats;
		IPv4Point src, dest;
		UDP_PACKET *udp;
		TCP_PACKET *tcp;
		switch (ipv4->protocol) {
		case IPPROTO_UDP:
			udp = (UDP_PACKET*)ipv4->payload();
			//cout << "receive" << endl;
			//cout << udp->payloadLength() << endl;
			//cout << std::hex;
			//for (int i = 0; i < udp->payloadLength(); i++) {
			//	cout << (unsigned short)udp->payload[i] << ' ';
			//}
			//cout << std::dec << endl;
			src = IPv4Point(IPPROTO_UDP, ipv4->src, udp->srcPort), dest = IPv4Point(IPPROTO_UDP, ipv4->dest, udp->destPort);
			if (natman.getSessionByLocalNext(dest, src, &nats)) {
				break;
			}
			nats->refresh(ipv4->id);
			ipv4->src = nats->dest.addr;
			ipv4->dest = nats->appLocal.addr;
			udp->srcPort = nats->dest.port;
			udp->destPort = nats->appLocal.port;
			ipv4->computeChecksum();
			udp->computeChecksum(ipv4->getFakeHeaderSum());

			if (WriteFile(adapter, ipv4, len, &len, &adapterWriteOverlap)) {
				DWORD error = GetLastError();
				if (error == ERROR_IO_PENDING)
					WaitForSingleObject(adapterWriteOverlap.hEvent, INFINITE);
				else
					pumpError("write adapter UDP", error);
			}
			break;
		case IPPROTO_TCP:
			tcp = (TCP_PACKET*)ipv4->payload();
			unsigned short payloadLen = tcp->payloadLength(ipv4->payloadLength());
			cout << "receive" << endl;
			cout << payloadLen << endl;
			src = IPv4Point(IPPROTO_TCP, ipv4->src, tcp->srcPort), dest = IPv4Point(IPPROTO_TCP, ipv4->dest, tcp->destPort);
			if (natman.getSessionByLocalNext(dest, src, &nats)) {
				break;
			}
			nats->refresh(ipv4->id);
			ipv4->src = nats->dest.addr;
			ipv4->dest = nats->appLocal.addr;
			tcp->srcPort = nats->dest.port;
			tcp->destPort = nats->appLocal.port;
			ipv4->computeChecksum();
			tcp->computeChecksum(ipv4->getFakeHeaderSum(), ipv4->payloadLength());

			if (WriteFile(adapter, ipv4, len, &len, &adapterWriteOverlap)) {
				DWORD error = GetLastError();
				if (error == ERROR_IO_PENDING)
					WaitForSingleObject(adapterWriteOverlap.hEvent, INFINITE);
				else
					pumpError("write adapter TCP", error);
			}
			break;
		}
	}
}