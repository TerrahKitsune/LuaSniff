#define _CRT_SECURE_NO_WARNINGS
#include "Network.h"

void DecodeMessage(char * buffer, int size, lua_State*L, const char * interf);
void CleanAll(SOCKET_INTERFACE *Sockets, int numbsockets);
void CheckWindowTitle(lua_State*L, char * current, int size);

typedef struct {

	BYTE * data;
	size_t len;
	int index;
}LastPacket;

void Reconnect(){


}

int main(int argc, const char* argv[]){

	//Vars
	
	WSADATA				wsa;
	SOCKET_INTERFACE*   Sockets = NULL;
	SOCKET_INTERFACE*   SocketsExtra = NULL;
	SOCKET_INTERFACE*   SocketsMerge = NULL;
	int					numbsocketsextra = 0;
	int					numbsockets=0;
	char*				packet = malloc(PACKET_SIZE_MAX);
	int					numbytes;
	DWORD				test = 0;
	lua_State*			L;
	int					pause = 0;
	int					n=0;
	int					hasMsg;
	Timer				T;
	int					Ticker;
	char				WindowTitle[128];
	int					PCAP = 0;
	pcap_if_t*			alldevs=NULL, *d;
	LastPacket*			lastpacket = (LastPacket*)malloc(sizeof(LastPacket));
	char				mainScript[MAX_PATH];

	if (argc >= 2){
		memset(mainScript,0,MAX_PATH*sizeof(char));
		strncpy(mainScript, argv[1], MAX_PATH - 1);
	}
	else{
		strcpy(mainScript,"main.lua");
	}

	SetDllDirectory("C:\\Windows\\System32\\Npcap\\");

	ZeroMemory(lastpacket, sizeof(LastPacket));

	lastpacket->data = malloc(PACKET_SIZE_MAX);

	WindowTitle[0] = '\0';

	//Init wsa
	WSAStartup(MAKEWORD(2, 2), &wsa);

	if (!packet || !lastpacket || !lastpacket->data){

		printf("malloc failed to allocate packet buffer\n");
		return -5;
	}

	//Lua
	L = luaL_newstate();
	if (!L){
		printf("Unable to start lua state\n");
		free(packet);
		free(lastpacket->data);
		free(lastpacket);
		_getch();
		return -6;
	}

	//Load all lua function libraries
	luaL_openlibs(L);
	LoadLibs(L);
	LoadNetLibs(L);

	if (!lua_ExecuteFile(L, mainScript)){
		printf("Failed to run %s\n", mainScript);
		free(packet);
		free(lastpacket->data);
		free(lastpacket);
		lua_close(L);
		_getch();
		return -7;
	}
	else if (!lua_CheckFunctionExists(L, "Recv")){
		printf("%s does not implement function Recv(packet,interface)\n", mainScript);
		free(packet);
		free(lastpacket->data);
		free(lastpacket);
		lua_close(L);
		_getch();
		return -8;
	}
	else{
		printf("ran %s\n", mainScript);
	}

	pause = lua_GetGlobalBoolean(L, "PAUSE");
	CheckWindowTitle(L, WindowTitle, 128);
	PCAP = lua_GetGlobalBoolean(L, "WINSOCK");

	if (PCAP<=0 && pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, packet) != -1){

		n = 0;

		//pcap enabled
		for (d = alldevs; d; d = d->next)
		{
			++n;
		}

		if (n<=0)
			pcap_freealldevs(alldevs);
	}

	ResolveIPTable(L);

	if (n>0){

		Sockets = PCAPConnectAll(L, packet, &numbsockets, pause, alldevs);

		if (Sockets == NULL){
			pcap_freealldevs(alldevs);
			free(packet);
			free(lastpacket->data);
			free(lastpacket);
			if (pause)
				_getch();
			return -5;
		}
	}
	
	if (abs(PCAP)>=1){
		
		//Init the socket; listen to everything

		SocketsExtra = ConnectAll(L, packet, &numbsocketsextra, pause);

		if (SocketsExtra == NULL){
			printf("No sockets connected!\n");
			free(packet);
			free(lastpacket->data);
			free(lastpacket);
			WSACleanup();
			lua_close(L);
			if (pause)
				_getch();
			return -5;
		}
		else if (numbsocketsextra <= 0){
			free(SocketsExtra);
			printf("No sockets connected!\n");
			free(packet);
			free(lastpacket->data);
			free(lastpacket);
			WSACleanup();
			lua_close(L);
			if (pause)
				_getch();
			return -6;
		}
	}

	if (PCAP==-1){

		SocketsMerge = (SOCKET_INTERFACE*)calloc(numbsockets + numbsocketsextra, sizeof(SOCKET_INTERFACE));

		if (Sockets){

			for (n = 0; n < numbsockets; n++){
				memcpy(&SocketsMerge[n], &Sockets[n], sizeof(SOCKET_INTERFACE));
			}
			free(Sockets);
		}

		if (SocketsExtra){
			for (n = 0; n < numbsocketsextra; n++){
				memcpy(&SocketsMerge[n + numbsockets], &SocketsExtra[n], sizeof(SOCKET_INTERFACE));
			}
			free(SocketsExtra);
		}
		

		Sockets = SocketsMerge;
		numbsockets += numbsocketsextra;
	}
	else if (PCAP == 1){
		Sockets = SocketsExtra;
		numbsockets = numbsocketsextra;
	}

	lua_RunTick(L);

	if (PCAP==-1)
		puts("Starting in PCAP/WINSOCK mode...");
	else if (PCAP==0)
		puts("Starting in PCAP mode...");
	else 
		puts("Starting in WINSOCK mode...");

	memset(&T, 0, sizeof(Timer));
	StartCounter(&T);
	while (TRUE){

		hasMsg = 0;

		for (n = 0; n < numbsockets; n++){	
			numbytes = HasData(&Sockets[n], packet, PACKET_SIZE_MAX);
			if (numbytes>0){

				//ignore packet if its the same as the last we pushed
				if (lastpacket->index != n && numbytes == lastpacket->len && lua_GetGlobalBoolean(L,"NODUP")!=0 && memcmp(packet, lastpacket->data, numbytes) == 0) {
					continue;
				}
				else {
					lastpacket->len = numbytes;
					memcpy(lastpacket->data, packet, numbytes);
					lastpacket->index = n;
				}

				DecodeMessage(packet, numbytes, L, &Sockets[n]);
				hasMsg = 1;
			}			
		}

		Ticker = lua_GetGlobalInt(L, "TICK", 0);

		if (Ticker >0 && GetCounter(&T) > Ticker){

			StartCounter(&T);

			if (lua_RunTick(L))
				break;
		}
		else if (!hasMsg){
			Sleep(1);
		}

		CheckWindowTitle(L, WindowTitle, 127);
	}

	//Cleanup
	if (PCAP){
		pcap_freealldevs(alldevs);
	}
	else{
		CleanAll(Sockets, numbsockets);
		WSACleanup();
	}

	lua_close(L);
	
	free(packet);
	free(lastpacket->data);
	free(lastpacket);
	
	//Press any key
	puts("Program terminated...");
	if (pause)
		_getch();
	return 0;
}

void CleanAll(SOCKET_INTERFACE *Sockets, int numbsockets){
	
	if (numbsockets > 0)
		return;
	
	if (!Sockets)
		return;

	int n;
	for (n = 0; n < numbsockets; n++){

		if (Sockets[n].fp)
			pcap_close(Sockets[n].fp);
		else
			closesocket(Sockets[n].Socket);

		if (Sockets[n].addr)
			free(Sockets[n].addr);

		if (Sockets[n].addrv6)
			free(Sockets[n].addrv6);
	}
	free(Sockets);
}

void DecodeMessage(char * buffer, int size, lua_State*L, SOCKET_INTERFACE * interf){
	
	int			ip_header_size = 0;
	int			ip_ver = HI_PART(buffer[0]);	

	//ipv4
	if (ip_ver == 4) {

		IPHEADER*	ip_header = (IPHEADER *)buffer;

		if (size < sizeof(IPHEADER))
			return;

		ip_header_size = LO_PART(ip_header->ver_ihl);
		ip_header_size *= sizeof(DWORD); // size in 32 bits words

		lua_IPv4PacketRecv(L, ip_header, &buffer[ip_header_size], interf->addr, interf->fp ? "pcap" : "winsock");
	}
	else if(ip_ver == 6) {

		if (size < sizeof(IPV6HEADER))
			return;

		IPV6HEADER*	ipv6_header = (IPV6HEADER *)buffer;
		
		lua_IPv6PacketRecv(L, ipv6_header, &buffer[sizeof(IPV6HEADER)], interf->addrv6, size, interf->fp ? "pcap" : "winsock");
	}
}


void CheckWindowTitle(lua_State*L, char * current, int size){
	
	char temp[128];

	if (lua_GetGlobalString(L, "TITLE", temp, 127)){

		if (strncmp(temp, current, size) != 0){
			SetConsoleTitle(temp);
			strncpy(current, temp, size - 1);
		}
	}
}