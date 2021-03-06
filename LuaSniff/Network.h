#pragma warning( disable: 4996 ) //Don't warn be about winsock deprication
#pragma warning( disable: 4013 ) //Don't warn about extern default ints

#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ws2tcpip.h>

#include "LuaEngine.h"

#define HAVE_REMOTE
#include "pcap.h"
#pragma comment (lib, "Ws2_32.lib")

#pragma comment (lib, "pcap/Lib/wpcap.lib")

#ifndef SIO_RCVALL
#define SIO_RCVALL    _WSAIOW(IOC_VENDOR,1)
#endif

typedef struct{
	double PCFreq;
	__int64 CounterStart;
}Timer;

typedef struct{
	pcap_t *fp;
	SOCKET Socket;
	char * addr;
	char * addrv6;
}SOCKET_INTERFACE;

SOCKET_INTERFACE * ConnectAll(lua_State*L, char * packet, int *numbsockets, int pause);
SOCKET_INTERFACE * PCAPConnectAll(lua_State*L, char * packet, int *numbsockets, int pause, pcap_if_t *alldevs);

void StartCounter(Timer * t);
double GetCounter(Timer * t);

void LoadNetLibs();

static int L_Resolve(lua_State *L);
static int L_GetOwnHost(lua_State *L);
static int L_ReverseDNS(lua_State *L);

//Resolves your hostname into an ip address
//returned char if not null should be freed
//If L is not null it'll push all addresses to the lua stack as an array
char * ResolveIP(const char * ip,lua_State*L);

//Takes the IP table, resolves it and re-pushes it
void ResolveIPTable(lua_State*L);

//Set socket buffer
void SetSocketBuffer(SOCKET socket, int buffsize);

//Open a socket for reading
SOCKET OpenReadAllSocket(const char * addr, int socketbuffersize);

//Fills the buffer with data if its been recived
//returns >0 if data arrived
int HasData(SOCKET_INTERFACE * socket, char * buffer, int size);

//Returns a buffer (should be free'd) containing an error message
//if print is true it'll print and return null
char * FormatErrorMessage(int error, BOOL print);