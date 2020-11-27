#include "stdafx.h"
#include "vr_route.h"

IPv4Point::IPv4Point() {}
IPv4Point::IPv4Point(unsigned char protocol, unsigned long addr, unsigned short port) :
	protocol(protocol), port(port), addr(addr)
{}

IPv4Point::IPv4Point(unsigned char protocol, const char* addrString, unsigned short hPort) :
	protocol(protocol)
{
	in_addr t;
	inet_pton(AF_INET, addrString, &t);
	addr = t.S_un.S_addr;
	port = htons(hPort);
}

bool IPv4Point::operator==(const IPv4Point& a) const {
	return (protocol == a.protocol)
		&& (port == a.port)
		&& (addr == addr);
}

size_t IPv4PointHasher::operator() (const pair<IPv4Point, IPv4Point>& t) const {
	size_t hash = 0;
	hash += t.first.port ^ t.second.protocol;
	hash += t.second.port ^ t.first.protocol;
	hash += t.first.addr ^ t.second.addr;
	return hash;
}

bool IPv4PointHasher::operator() (const pair<IPv4Point, IPv4Point>& a, const pair<IPv4Point, IPv4Point>& b) const {
	return memcmp(&a, &b, sizeof(pair<IPv4Point, IPv4Point>)) == 0;
}

void GatewaySession::refreshRoute(const unsigned short& packetID, const time_t& time) {
	unsigned short IDres = packetID - lastID;
	if (IDres < 1024) {
		lastID = packetID;
		if (lastActive && IDres > 1)
			std::cout << "Drop " << IDres << "packet(s) at" << ntohs(packetID) << std::endl;
	}
	lastActive = time;
}

DWORD GatewaySession::init(MIB_IPADDRTABLE* addrTable) {
	if (isEnabled)
		return 0;
	DWORD ifIndex;
	DWORD rs = GetBestInterface(nextIPv4, &ifIndex);
	if (rs)
		return rs;

	for (size_t i = 0; i < addrTable->dwNumEntries; i++)
		if (addrTable->table[i].dwIndex == ifIndex)
			localIPv4 = addrTable->table[i].dwAddr;

	cout << localIPv4 << std::endl;
	sockaddr_in local, next;
	local.sin_addr.S_un.S_addr = localIPv4;
	local.sin_family = AF_INET;
	next.sin_addr.S_un.S_addr = nextIPv4;
	next.sin_family = AF_INET;

	socket = WSASocket(AF_INET, SOCK_RAW, IPPROTO_IP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (socket == INVALID_SOCKET)
		return GetLastError();
	if (setsockopt(socket, IPPROTO_IP, IP_HDRINCL, (char*)&on, sizeof DWORD))
		return GetLastError();
	if (bind(socket, (sockaddr*)&local, sizeof(local)))
		return GetLastError();
	if (connect(socket, (sockaddr*)&next, sizeof(next)))
		return GetLastError();

	memset(&recvOverlap, 0, sizeof(OVERLAPPED));
	memset(&sendOverlap, 0, sizeof(OVERLAPPED));
	recvOverlap.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	sendOverlap.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	isEnabled = true;
	return 0;
}


GatewaySession::GatewaySession(unsigned long& nextIPv4) :
	nextIPv4(nextIPv4)
{
}

GatewaySession::~GatewaySession() {
	if (isEnabled) {
		closesocket(socket);
		CloseHandle(recvOverlap.hEvent);
		CloseHandle(sendOverlap.hEvent);
	}
}

NATSession::NATSession(const IPv4Point& dest, const IPv4Point& next, const IPv4Point& appLocal, const IPv4Point& routerLocal, const PTRGTWS& route) :
	dest(dest), next(next), appLocal(appLocal), routerLocal(routerLocal), route(route)
{
}

NATSession::NATSession() {
}

NATSession::~NATSession() {
}

void NATSession::refresh(const unsigned short& netPacketID) {
	lastActive = std::time(NULL);
	route->refreshRoute(ntohs(netPacketID), lastActive);
}

unsigned short NATManager::allocPort() {
	if (portCount == PORT_NUMBER)
		return 0;
	while (localPorts.test(nextPort - BEGIN_PORT)) {
		nextPort++;
		if (nextPort == END_PORT)
			nextPort = BEGIN_PORT;
	}
	int t = nextPort - BEGIN_PORT;
	localPorts.set(t);
	nextPort++;
	portCount++;
	if (nextPort == END_PORT)
		nextPort = BEGIN_PORT;
	return t + BEGIN_PORT;
}
void NATManager::releasePort(unsigned short& port) {
	if (port >= BEGIN_PORT && port < END_PORT && localPorts.test(port - BEGIN_PORT)) {
		portCount--;
		localPorts.reset(port - BEGIN_PORT);
	}
}

NATManager::~NATManager() {

}
PTRNATS NATManager::registerSession(const NATSession& sess) {
	natSessList.push_front(sess);
	PTRNATS iterator = natSessList.begin();
	local_nextMap.insert(make_pair(make_pair(sess.routerLocal, sess.next), iterator));
	dest_appMap.insert(make_pair(make_pair(sess.dest, sess.appLocal), iterator));
	return iterator;
}
PTRGTWS NATManager::registerGateway(const char* str) {
	unsigned long ip;
	inet_pton(AF_INET, str, &ip);
	return registerGateway(GatewaySession(ip));
}
PTRGTWS NATManager::registerGateway(const GatewaySession& t) {
	gatewaySessList.push_front(t);
	return gatewaySessList.begin();
}
DWORD NATManager::addRoute(const char* dest, const PTRGTWS& next) {
	unsigned long ip;
	inet_pton(AF_INET, dest, &ip);
	return addRoute(ip, next);
}
DWORD NATManager::addRoute(const unsigned long& dest, const PTRGTWS& next) {
	MIB_IPFORWARDROW row;
	row.dwForwardDest = dest;
	row.dwForwardIfIndex = vitualInterfaceID;
	row.dwForwardMask = 0xFFFFFFFF;
	row.dwForwardMetric1 = 1;
	row.dwForwardNextHop = 16843018;
	row.dwForwardProto = MIB_IPPROTO_NETMGMT;
	DWORD rs = CreateIpForwardEntry(&row);
	if (!rs)
		dest_nextRoute[dest] = next;
	return rs;
}


DWORD NATManager::setup() {
	ULONG virtualLocal, virtualGatweay, virtualMask, virtualNet;
	inet_pton(AF_INET, "10.1.1.2", &virtualLocal);
	inet_pton(AF_INET, "10.1.1.1", &virtualGatweay);
	inet_pton(AF_INET, "255.255.255.0", &virtualMask);
	inet_pton(AF_INET, "10.1.1.0", &virtualNet);
	MIB_IPADDRTABLE* addrTable = NULL;
	DWORD size = 0;
	DWORD rs = GetIpAddrTable(addrTable, &size, FALSE);
	if (rs != ERROR_INSUFFICIENT_BUFFER)
		return rs;

	addrTable = (MIB_IPADDRTABLE*)new byte[size];
	if (rs = GetIpAddrTable(addrTable, &size, FALSE))
		return rs;
	char t[16];
	inet_ntop(AF_INET, &virtualNet, t, 16);
	cout << "IP Net:             " << t << '\n\n';
	for (size_t i = 0; i < addrTable->dwNumEntries; i++) {
		if (addrTable->table[i].dwAddr == virtualLocal) { // 10.1.1.2
			vitualInterfaceID = addrTable->table[i].dwIndex;

			//break;
		}
		inet_ntop(AF_INET, &addrTable->table[i].dwAddr, t, 16);
		cout << "IP Address:         " << t << '\n';
		inet_ntop(AF_INET, &addrTable->table[i].dwMask, t, 16);
		cout << "IP Mask:            " << t << '\n';

		cout << "IF Index:           " << addrTable->table[i].dwIndex << '\n';
		cout << "Broadcast Addr:     " << addrTable->table[i].dwBCastAddr << '\n';
		cout << "Re-assembly size:   " << addrTable->table[i].dwReasmSize << '\n';
	}
	cout << std::flush;
	for (auto& t : gatewaySessList) {
		if (rs = t.init(addrTable))
			return rs;
	}
	delete[size] addrTable;

	MIB_IPFORWARDTABLE* forwardTable = NULL;
	size = 0;
	rs = GetIpForwardTable(forwardTable, &size, FALSE);
	if (rs != ERROR_INSUFFICIENT_BUFFER)
		return rs;

	forwardTable = (MIB_IPFORWARDTABLE*)new byte[size];
	if (rs = GetIpForwardTable(forwardTable, &size, FALSE))
		return rs;

	for (size_t i = 0; i < forwardTable->dwNumEntries; i++) {
		MIB_IPFORWARDROW& row = forwardTable->table[i];
		ULONG net = (row.dwForwardDest & row.dwForwardMask & virtualMask);
		if (row.dwForwardIfIndex == vitualInterfaceID || net == virtualNet)//10.1.1.1
			if (row.dwForwardIfIndex != vitualInterfaceID || net != virtualNet) {
				cout << "Deleting \n";
				inet_ntop(AF_INET, &row.dwForwardDest, t, 16);
				cout << "IP Address:         " << t << '\n';
				inet_ntop(AF_INET, &row.dwForwardMask, t, 16);
				cout << "IP Mask:            " << t << '\n';
				inet_ntop(AF_INET, &net, t, 16);
				cout << "IP Net:             " << t << '\n';

				cout << "IF Index:           " << row.dwForwardIfIndex << '\n';
				if (rs = DeleteIpForwardEntry(&row))
					return rs;
				cout << "Deleted\n";
			}
	}
	delete[size] forwardTable;
	nextPort = BEGIN_PORT + (std::rand() % PORT_NUMBER);
	isEnabled = true;
	return 0;
}

DWORD NATManager::getSessionByLocalNext(IPv4Point local, IPv4Point next, PTRNATS* result) const {
	if (local.protocol != next.protocol)
		return TRUE;
	auto it = local_nextMap.find(make_pair(local, next));
	if (it == local_nextMap.end())
		return TRUE;
	*result = it->second;
	return FALSE;
}
DWORD NATManager::getSessionByDestApp(IPv4Point dest, IPv4Point appLocal, PTRNATS* result) {
	if (dest.protocol != appLocal.protocol)
		return TRUE;
	unsigned char protocol = dest.protocol;
	auto it = dest_appMap.find(make_pair(dest, appLocal));
	if (it == dest_appMap.end()) {
		// Create New Session
		//for (auto a : dest_nextRoute) {
		//	std::cout << a.first.port << std::endl;;
		//}
		std::cout << "New " << (int)protocol << std::endl;
		auto nextIt = dest_nextRoute.find(dest.addr);
		if (nextIt == dest_nextRoute.end())
			return TRUE;
		unsigned short port = allocPort();
		if (port == 0)
			return TRUE;
		IPv4Point routerLocal = IPv4Point(protocol, nextIt->second->getLocal(), htons(port));
		NATSession newNats = NATSession(dest, IPv4Point(protocol, nextIt->second->nextIPv4, dest.port), appLocal, routerLocal, nextIt->second);
		// temporarily put a endpoint of NEXT with the same port.
		*result = registerSession(newNats);
		return FALSE;
	}
	*result = it->second;
	return FALSE;
}