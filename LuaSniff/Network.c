#include "Network.h"

void LoadNetLibs(lua_State *L){
	lua_pushcfunction(L, L_Resolve);
	lua_setglobal(L, "dns");

	lua_pushcfunction(L, L_GetOwnHost);
	lua_setglobal(L, "GetHostName");
}

static int L_Resolve(lua_State *L) {

	size_t len;
	const char * addr = luaL_tolstring(L, 1, &len);
	char * ip = ResolveIP(addr);

	lua_pop(L, 1);

	if (ip){
		lua_pushstring(L, ip);
		free(ip);
	}
	else{
		lua_pushnil(L);
	}

	return 1;
}

static int L_GetOwnHost(lua_State *L){
	
	char buf[128];
	buf[0] = '\0';
	gethostname(buf, 128);

	lua_pushstring(L, buf);
	return 1;
}

SOCKET OpenReadAllSocket(const char * addr, int socketbuffersize){

	SOCKET				listen_socket = -1;
	struct sockaddr_in	socketdata;
	int					opt = 1;
	DWORD				dwLen = 0;
	unsigned long		ul = 1;

	listen_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (listen_socket == SOCKET_ERROR)
	{
		return SOCKET_ERROR;
	}

	socketdata.sin_family = AF_INET;
	socketdata.sin_port = htons(0);
	socketdata.sin_addr.s_addr = inet_addr(addr);

	if (bind(listen_socket, (struct sockaddr *)&socketdata, sizeof(socketdata)) == SOCKET_ERROR)
	{
		closesocket(listen_socket);
		return SOCKET_ERROR;
	}

	SetSocketBuffer(listen_socket, socketbuffersize);

	ioctlsocket(listen_socket, FIONBIO, &ul);

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
		closesocket(listen_socket);
		return SOCKET_ERROR;
	}

	return listen_socket;
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
}

int HasData(SOCKET socket, char * buffer, int size){

	int bytes = recv(socket, buffer, size, 0);
	int error;

	if (bytes < 0){

		error = WSAGetLastError();

		if (error == WSAEWOULDBLOCK)
			return 0;
		else
			return SOCKET_ERROR;
	}

	return bytes;
}

void StartCounter(Timer * t)
{
	ZeroMemory(t, sizeof(Timer));
	LARGE_INTEGER li;
	QueryPerformanceFrequency(&li);

	t->PCFreq = ((double)li.QuadPart) / 1000.0;

	QueryPerformanceCounter(&li);
	t->CounterStart = li.QuadPart;
}
double GetCounter(Timer * t)
{
	LARGE_INTEGER li;
	QueryPerformanceCounter(&li);
	return ((double)li.QuadPart - t->CounterStart) / t->PCFreq;
}