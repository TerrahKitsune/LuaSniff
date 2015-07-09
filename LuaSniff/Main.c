#define _CRT_SECURE_NO_WARNINGS
#pragma warning( disable: 4996 ) //Don't warn be about winsock deprication
#pragma warning( disable: 4013 ) //Don't warn about extern default ints

#include <winsock2.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ws2tcpip.h>

#include "LuaEngine.h"

#pragma comment (lib, "Ws2_32.lib")

#ifndef SIO_RCVALL
	#define SIO_RCVALL    _WSAIOW(IOC_VENDOR,1)
#endif

//Resolves your hostname into an ip address
//returned char if not null should be freed
char * ResolveIP(const char * ip);

void SetSocketBuffer(SOCKET socket, int buffsize);

int main(int argc, const char* argv[]){

	//Vars
	char				host[128];
	WSADATA				wsa;
	SOCKET				listen_socket = -1;
	char*				listenIP;
	struct sockaddr_in	socketdata;
	int					opt = 1;
	DWORD				dwLen = 0;
	char*				packet = malloc(PACKET_SIZE_MAX);
	int					numbytes;
	IPHEADER*			ip_header = NULL;
	DWORD				test = 0;
	int					ip_header_size = 0;
	lua_State*			L;
	int					pause = 0;

	if (!packet){

		printf("malloc failed to allocate packet buffer\n");
		return -5;
	}

	//Lua
	L = luaL_newstate();
	if (!L){
		printf("Unable to start lua state\n");
		free(packet);
		closesocket(listen_socket);
		WSACleanup();
		_getch();
		return -6;
	}

	//Load all lua function libraries
	luaL_openlibs(L);

	if (!lua_ExecuteFile(L, "main.lua")){
		printf("Failed to run main.lua\n");
		free(packet);
		closesocket(listen_socket);
		WSACleanup();
		lua_close(L);
		_getch();
		return -7;
	}
	else if (!lua_CheckFunctionExists(L, "Recv")){
		printf("main.lua does not implement function Recv(packet)\n");
		free(packet);
		closesocket(listen_socket);
		WSACleanup();
		lua_close(L);
		_getch();
		return -8;
	}

	pause = lua_GetGlobalBoolean(L, "PAUSE");

	//Init wsa
	WSAStartup(MAKEWORD(2, 2), &wsa);

	//Init the socket; listen to everything
	listen_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (listen_socket == SOCKET_ERROR)
	{
		printf("Socket error: %d\n", WSAGetLastError());
		free(packet);
		WSACleanup();
		if (pause)
			_getch();
		return -1;
	}

	if (!lua_GetGlobalString(L, "IP", host, 128)){
		gethostname(host, 128);
	}
	
	
	listenIP = ResolveIP(host);
	
	//Figure which IP we want to listen too
	if (!listenIP){
		free(packet);
		closesocket(listen_socket);
		WSACleanup();
		return -2;
		if (pause)
			_getch();
	}

	socketdata.sin_family = AF_INET;
	socketdata.sin_port = htons(0);
	socketdata.sin_addr.s_addr = inet_addr(listenIP);

	if (bind(listen_socket, (struct sockaddr *)&socketdata, sizeof(socketdata)) == SOCKET_ERROR)
	{
		printf("Bind error: d\n", WSAGetLastError());
		free(packet);
		closesocket(listen_socket);
		WSACleanup();
		return -3;
		if (pause)
			_getch();
	}

	printf("Bind IP: %s\n",listenIP);

	SetSocketBuffer(listen_socket, lua_GetGlobalInt(L,"BUFFER",0));
	lua_SetGlobalString(L, "IP", listenIP);

	// Set socket to promiscuous mode
	if (WSAIoctl(listen_socket,
		SIO_RCVALL,
		&opt,
		sizeof(opt),
		NULL,
		0,
		&dwLen,
		NULL,
		NULL) == SOCKET_ERROR)

	{
		printf("WSAIoctl error: %l\n", WSAGetLastError());
		free(packet);
		closesocket(listen_socket);
		WSACleanup();
		return -4;
		if (pause)
			_getch();
	}	

	puts("Starting...");

	while (TRUE){

		//Clear out the buffer
		memset(packet, 0, sizeof(PACKET_SIZE_MAX));

		numbytes = recv(listen_socket, packet, PACKET_SIZE_MAX, 0);
		if (numbytes < sizeof(IPHEADER))
			continue;

		ip_header = (IPHEADER *)packet;

		//ipv4 check
		if (HI_PART(ip_header->ver_ihl) != 4)
			continue;

		ip_header_size = LO_PART(ip_header->ver_ihl);
		ip_header_size *= sizeof(DWORD); // size in 32 bits words

		lua_PacketRecv(L, ip_header, &packet[ip_header_size]);
	}

	//Cleanup
	lua_close(L);
	WSACleanup();
	free(listenIP);
	free(packet);

	//Press any key
	puts("Program terminated...");
	if (pause)
		_getch();
	return 0;
}

char * ResolveIP(const char * ip)
{
	char				host[128];
	ADDRINFO			*result;
	int					resultcode;
	struct addrinfo		*ptr = NULL;
	char				*ret = NULL;
	int					size;

	resultcode = getaddrinfo(ip, NULL, NULL, &result);

	if (resultcode != 0){

		printf("GetDefaultIP() Error: %d\n", resultcode);
		return NULL;
	}

	//Loop the results
	host[0] = '\0';
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next){

		//Take the first ip4 we find
		if (ptr->ai_family == AF_INET){
			InetNtop(AF_INET, &((struct sockaddr_in *) ptr->ai_addr)->sin_addr, host, 128);
			break;
		}
	}

	if (host[0] == '\0'){
		printf("GetDefaultIP() Error: found no ip4 address\n");
		return NULL;
	}

	size = strlen(host) + 1;
	ret = malloc(size);
	memset(ret, 0, size);

	strcpy(ret, host);

	return ret;
}

void SetSocketBuffer(SOCKET socket, int buffsize){

	if (buffsize <= 0)
		return;

	int bufferLength;
	int bufferLengthPtrSize = sizeof(int);


	setsockopt(socket, SOL_SOCKET, SO_RCVBUF, (char *)&buffsize, sizeof(buffsize));
	setsockopt(socket, SOL_SOCKET, SO_SNDBUF, (char *)&buffsize, sizeof(buffsize));

	getsockopt(socket, SOL_SOCKET, SO_RCVBUF, (char *)&bufferLength, &bufferLengthPtrSize);

	printf("Socket recv/send buffer set to %d bytes\n", bufferLength);
}