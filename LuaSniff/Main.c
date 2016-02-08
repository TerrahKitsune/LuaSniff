#define _CRT_SECURE_NO_WARNINGS
#include "Network.h"

void DecodeMessage(char * buffer, int size, lua_State*L, const char * interf);
void CleanAll(SOCKET_INTERFACE *Sockets, int numbsockets);
void CheckWindowTitle(lua_State*L, char * current, int size);

void Reconnect(){


}

int main(int argc, const char* argv[]){

	//Vars
	
	WSADATA				wsa;
	SOCKET_INTERFACE*   Sockets = NULL;
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

	WindowTitle[0] = '\0';

	if (!packet){

		printf("malloc failed to allocate packet buffer\n");
		return -5;
	}

	//Lua
	L = luaL_newstate();
	if (!L){
		printf("Unable to start lua state\n");
		free(packet);
		_getch();
		return -6;
	}

	//Load all lua function libraries
	luaL_openlibs(L);
	LoadLibs(L);
	LoadNetLibs(L);

	if (!lua_ExecuteFile(L, "main.lua")){
		printf("Failed to run main.lua\n");
		free(packet);
		lua_close(L);
		_getch();
		return -7;
	}
	else if (!lua_CheckFunctionExists(L, "Recv")){
		printf("main.lua does not implement function Recv(packet,interface)\n");
		free(packet);
		lua_close(L);
		_getch();
		return -8;
	}

	pause = lua_GetGlobalBoolean(L, "PAUSE");
	CheckWindowTitle(L, WindowTitle, 128);

	if (lua_GetGlobalBoolean(L, "WINSOCK")){
		PCAP = 0;
	}
	else if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, packet) != -1){
		//pcap enabled
		for (d = alldevs; d; d = d->next)
		{
			++n;
		}

		PCAP = n>0;
		if (PCAP==0)
			pcap_freealldevs(alldevs);
	}


	if (PCAP){

		Sockets = PCAPConnectAll(L, packet, &numbsockets, pause, alldevs);

		if (Sockets == NULL){
			pcap_freealldevs(alldevs);
			free(packet);
			if (pause)
				_getch();
			return -5;
		}

	}
	else{
		//Init wsa
		WSAStartup(MAKEWORD(2, 2), &wsa);

		//Init the socket; listen to everything

		Sockets = ConnectAll(L, packet, &numbsockets, pause);

		if (Sockets == NULL){
			printf("No sockets connected!\n");
			free(packet);
			WSACleanup();
			lua_close(L);
			if (pause)
				_getch();
			return -5;
		}
		else if (numbsockets <= 0){
			free(Sockets);
			printf("No sockets connected!\n");
			free(packet);
			WSACleanup();
			lua_close(L);
			if (pause)
				_getch();
			return -6;
		}
	}

	lua_RunTick(L);

	if (PCAP)
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
				DecodeMessage(packet, numbytes, L, Sockets[n].addr);
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
	}
	free(Sockets);
}

void DecodeMessage(char * buffer, int size, lua_State*L, const char * interf){
	
	int			ip_header_size = 0;
	int			ip_ver = HI_PART(buffer[0]);	

	//ipv4
	if (ip_ver == 4) {

		IPHEADER*	ip_header = (IPHEADER *)buffer;

		if (size != htons(ip_header->length)) {
			return;
		}

		ip_header_size = LO_PART(ip_header->ver_ihl);
		ip_header_size *= sizeof(DWORD); // size in 32 bits words

		lua_IPv4PacketRecv(L, ip_header, &buffer[ip_header_size], interf);
	}
	else if(ip_ver == 6) {

		if (size < sizeof(IPV6HEADER))
			return;

		IPV6HEADER*	ipv6_header = (IPV6HEADER *)buffer;
		
		lua_IPv6PacketRecv(L, ipv6_header, &buffer[sizeof(IPV6HEADER)], interf, size);
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