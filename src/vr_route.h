#pragma once

#include <unordered_map>
#include <list>
#include <utility>
#include <bitset>
#include <iostream>
#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
using std::unordered_map;
using std::vector;
using std::list;
using std::pair;
using std::make_pair;
using std::bitset;
using std::cout;

const DWORD on = TRUE;
const DWORD MTU = 1500;
class IPv4Point {
public:
	unsigned char protocol = 0;
	unsigned short port = 0;//network byte order
	unsigned long addr = 0;
	IPv4Point();
	IPv4Point(unsigned char protocol, unsigned long addr, unsigned short port);
	IPv4Point(unsigned char protocol, const char* addrString, unsigned short hPort);
	bool operator==(const IPv4Point& a) const;
};

const unsigned int hashSeed = 19260817;
class IPv4PointHasher {
public:
	size_t operator() (const pair<IPv4Point, IPv4Point>& t) const;
	bool operator() (const pair<IPv4Point, IPv4Point>& a, const pair<IPv4Point, IPv4Point>& b) const;
};

class GatewaySession {
	time_t lastActive = 0;
	unsigned short lastID = 0;
	unsigned long localIPv4 = 0;
	SOCKET socket = NULL;
	OVERLAPPED recvOverlap, sendOverlap;
	bool isEnabled = false;
public:
	const unsigned long nextIPv4;
	byte recvBuffer[MTU];
	DWORD dataRecv;
	void refreshRoute(const unsigned short& packetID, const time_t& time);

	DWORD init(MIB_IPADDRTABLE* addrTable);

	inline const unsigned long getLocal() const {
		return localIPv4;
	}

	inline HANDLE getRecvEvent() const {
		return recvOverlap.hEvent;
	}

	inline HANDLE getSendEvent() const {
		return sendOverlap.hEvent;
	}

	inline bool socketReadAsync() {
		return ReadFile((HANDLE)socket, recvBuffer, MTU, &dataRecv, &recvOverlap);
	}

	inline bool getSocketReadResult() {
		return GetOverlappedResult((HANDLE)socket, &recvOverlap, &dataRecv, FALSE);
	}

	inline DWORD socketWriteSync(void* data, DWORD len) {
		if (WriteFile((HANDLE)socket, data, len, &len, &sendOverlap)) {
			DWORD error = GetLastError();
			if (error == ERROR_IO_PENDING) {
				WaitForSingleObject(sendOverlap.hEvent, INFINITE);
				if (GetOverlappedResult((HANDLE)socket, &sendOverlap, &dataRecv, FALSE))
					return GetLastError();
			}
			else
				return error;
		}
		return 0;
	}
	GatewaySession(unsigned long& nextIPv4);
	~GatewaySession();
};

using PTRGTWS = list<GatewaySession>::iterator;

class NATSession {
	time_t lastActive = 0;
public:
	const PTRGTWS route;
	const IPv4Point dest, next, appLocal, routerLocal;
	NATSession(const IPv4Point& dest, const IPv4Point& next, const IPv4Point& appLocal, const IPv4Point& routerLocal, const PTRGTWS& route);

	NATSession();
	~NATSession();

	void refresh(const unsigned short& netPacketID);
	
};

using PTRNATS = list<NATSession>::iterator;

class NATManager {
#define BEGIN_PORT 10240
#define END_PORT 20480
	static const USHORT PORT_NUMBER = END_PORT - BEGIN_PORT;
	unordered_map<pair<IPv4Point, IPv4Point>, PTRNATS, IPv4PointHasher> local_nextMap, dest_appMap;
	unordered_map<unsigned long, PTRGTWS> dest_nextRoute;
	list<GatewaySession> gatewaySessList;
	list<NATSession> natSessList;
	DWORD vitualInterfaceID; 
	bool isEnabled = false;
	bitset<PORT_NUMBER> localPorts;
	unsigned short nextPort, portCount = 0;

	unsigned short allocPort();
	void releasePort(unsigned short& port);
public:
	~NATManager();
	PTRNATS registerSession(const NATSession& sess);
	PTRGTWS registerGateway(const char* str);
	PTRGTWS registerGateway(const GatewaySession& t);
	DWORD addRoute(const char* dest, const PTRGTWS& next);
	DWORD addRoute(const unsigned long& dest, const PTRGTWS& next);
	inline PTRGTWS gatewaySessionBegin() {
		return gatewaySessList.begin();
	}
	inline PTRGTWS gatewaySessionEnd() {
		return gatewaySessList.end();
	}
	inline size_t gatewaySessionNum() const {
		return gatewaySessList.size();
	}


	DWORD setup();

	DWORD getSessionByLocalNext(IPv4Point local, IPv4Point next, PTRNATS* result) const;
	DWORD getSessionByDestApp(IPv4Point dest, IPv4Point appLocal, PTRNATS* result);
};