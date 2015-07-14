#include "Network.h"

typedef struct{
	SOCKET Socket;
	char * addr;
}SOCKET_INTERFACE;

void DecodeMessage(char * buffer, int size, lua_State*L, const char * interf);
SOCKET_INTERFACE * ConnectAll(lua_State*L, char * packet, int *numbsockets, int pause);
void CleanAll(SOCKET_INTERFACE *Sockets, int numbsockets);

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
	int					n;
	int					hasMsg;
	Timer				T;
	int					Ticker;

	if (!packet){

		printf("malloc failed to allocate packet buffer\n");
		return -5;
	}

	//Lua
	L = luaL_newstate();
	if (!L){
		printf("Unable to start lua state\n");
		free(packet);
		WSACleanup();
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
		WSACleanup();
		lua_close(L);
		_getch();
		return -7;
	}
	else if (!lua_CheckFunctionExists(L, "Recv")){
		printf("main.lua does not implement function Recv(packet,interface)\n");
		free(packet);
		WSACleanup();
		lua_close(L);
		_getch();
		return -8;
	}

	pause = lua_GetGlobalBoolean(L, "PAUSE");

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

	puts("Starting...");
	memset(&T, 0, sizeof(Timer));
	StartCounter(&T);
	while (TRUE){

		hasMsg = 0;

		for (n = 0; n < numbsockets; n++){		
			numbytes = HasData(Sockets[n].Socket, packet, PACKET_SIZE_MAX);
			if (numbytes>0){
				DecodeMessage(packet, numbytes, L, Sockets[n].addr);
				hasMsg = 1;
			}			
		}	

		Ticker = lua_GetGlobalInt(L, "TICK", 0);

		if (Ticker >0 && GetCounter(&T) > Ticker){

			if (lua_RunTick(L))
				break;

			StartCounter(&T);
		}
		else if (!hasMsg){
			Sleep(1);
		}
	}

	//Cleanup
	CleanAll(Sockets,numbsockets);
	lua_close(L);
	WSACleanup();
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
		closesocket(Sockets[n].Socket);
		if (Sockets[n].addr)
			free(Sockets[n].addr);
	}
	free(Sockets);
}

void DecodeMessage(char * buffer, int size, lua_State*L, const char * interf){

	IPHEADER*	ip_header = NULL;
	int			ip_header_size = 0;

	if (size < sizeof(IPHEADER))
		return;

	ip_header = (IPHEADER *)buffer;

	//ipv4 check
	if (HI_PART(ip_header->ver_ihl) != 4)
		return;

	ip_header_size = LO_PART(ip_header->ver_ihl);
	ip_header_size *= sizeof(DWORD); // size in 32 bits words

	lua_PacketRecv(L, ip_header, &buffer[ip_header_size], interf);
}

SOCKET_INTERFACE * ConnectAll(lua_State*L, char * packet, int *numbsockets, int pause){

	*numbsockets = 0;
	SOCKET_INTERFACE* Sockets = NULL;
	SOCKET Current;
	int n;
	const char * lstr;
	char * listenIP = NULL;
	char host[128];
	int buffer = lua_GetGlobalInt(L, "BUFFER", 0);

	lua_getglobal(L, "IP");
	if (lua_type(L, -1) == LUA_TTABLE){

		lua_pushnil(L);

		while (lua_next(L, -2)){
			if (lua_isstring(L, -1)){
				(*numbsockets)++;
			}
			lua_pop(L, 1);
		}

		lua_pop(L, 1);

		if (numbsockets <= 0){
			puts("IP Table contains no string values\n");
			if (pause)
				_getch();
			return NULL;
		}

		Sockets = (SOCKET_INTERFACE*)calloc(*numbsockets, sizeof(SOCKET_INTERFACE));

		lua_getglobal(L, "IP");
		lua_pushnil(L);

		n = 0;
		while (lua_next(L, -2)){
			if (lua_isstring(L, -1)){

				lstr = lua_tostring(L, -1);
				Sockets[n].addr = ResolveIP(lstr);

				if (!Sockets[n].addr){
					printf("Unable to resolve address: %s\n", lstr);
					(*numbsockets)--;
					if (pause)
						_getch();
					continue;
				}

				Sockets[n].Socket = OpenReadAllSocket(Sockets[n].addr, buffer);

				if (Sockets[n].Socket == SOCKET_ERROR){
					printf("Unable to create socket for address: %s\n", Sockets[n].addr);
					(*numbsockets)--;
					if (pause)
						_getch();
					continue;
				}

				printf("Connected: %s\n", Sockets[n].addr);
				n++;
			}
			lua_pop(L, 1);
		}

		lua_pop(L, 1);

		//Now push the addresses
		lua_newtable(L);

		for (n = 0; n < *numbsockets; n++){
			lua_pushinteger(L, Sockets[n].Socket);
			lua_pushstring(L, Sockets[n].addr);
			lua_settable(L, -3);
		}
		lua_setglobal(L, "IP");
	}
	else{
		lua_pop(L, 1);

		if (!lua_GetGlobalString(L, "IP", host, 128)){
			gethostname(host, 128);
		}

		listenIP = ResolveIP(host);

		if (!listenIP){
			printf("Unable to resolve address: %s\n", listenIP);
			if (pause)
				_getch();
			return NULL;
		}

		Current = OpenReadAllSocket(listenIP, buffer);

		if (Current == SOCKET_ERROR){
			printf("Failed to open socket with address: %s\n", listenIP);
			closesocket(Current);
			free(listenIP);
			if (pause)
				_getch();
			return NULL;
		}
		else{
			Sockets = (SOCKET_INTERFACE*)calloc(1, sizeof(SOCKET_INTERFACE));

			Sockets[0].Socket = Current;
			Sockets[0].addr = listenIP;

			*numbsockets = 1;
			lua_SetGlobalString(L, "IP", listenIP);
			printf("Opened single interface %s\n", listenIP);
		}
	}

	return Sockets;
}