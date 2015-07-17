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

SOCKET_INTERFACE * PCAPConnectAll(lua_State*L, char * packet, int *numbsockets, int pause, pcap_if_t *alldevs){

	SOCKET_INTERFACE* Sockets = NULL;
	int n=0;
	*numbsockets = 0;
	pcap_t *fp;
	int buffer = lua_GetGlobalInt(L, "BUFFER", 0);
	pcap_if_t*			_alldevs, *d;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_addr *addr;
	const char * temp;
	char host[128];
	char * str;
	char ** resolvecache;
	int cachesize = 0;

	if (buffer < 1500)
		buffer = 1500;

	for (d = alldevs; d; d = d->next)(*numbsockets)++;

	if (*numbsockets <= 0)
		return NULL;

	//Resolve ip's in IP global

	lua_getglobal(L, "IP");
	if (lua_type(L, -1) == LUA_TTABLE){

		lua_pushnil(L);

		while (lua_next(L, -2)){
			if (lua_isstring(L, -1)){
				n++;
			}
			lua_pop(L, 1);
		}

		lua_pop(L, 1);

		resolvecache = (char**)calloc(n, sizeof(char*));
		cachesize = n;
		lua_getglobal(L, "IP");

		lua_pushnil(L);
		n = 0;
		while (lua_next(L, -2)){
			if (lua_isstring(L, -1)){
				resolvecache[n++] = ResolveIP(lua_tostring(L,-1));
			}
			lua_pop(L, 1);
		}
		lua_pop(L, 1);

		lua_newtable(L);

		for (n = 0; n < cachesize; n++){
			if (resolvecache[n]){
				lua_pushinteger(L, n);
				lua_pushstring(L, resolvecache[n]);
				lua_settable(L, -3);
			}
		}
		lua_setglobal(L, "IP");

		for (n = 0; n < cachesize; n++){
			if (resolvecache[n])
				free(resolvecache[n]);
		}

		free(resolvecache);
	}

	else if (lua_type(L, -1) == LUA_TSTRING){
		str = ResolveIP(lua_tostring(L,-1));
		if (str){
			lua_pop(L, 1);
			lua_SetGlobalString(L, "IP", host);
			free(str);
		}
		else
		{
			lua_pop(L, 1);
			gethostname(host, 127);
			str = ResolveIP(lua_tostring(L, -1));
			if (!str){
				return NULL;
			}
			lua_SetGlobalString(L, "IP", str);
			free(str);
		}
	}
	else{
		lua_pop(L, 1);
		gethostname(host, 127);
		str = ResolveIP(host);
		if (!str){
			return NULL;
		}
		lua_SetGlobalString(L, "IP", str);
		free(str);
	}

	Sockets = (SOCKET_INTERFACE*)calloc(*numbsockets, sizeof(SOCKET_INTERFACE));

	for (d = alldevs; d; d = d->next){

		fp = pcap_open(d->name,
			buffer /*snaplen*/,
			PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
			20 /*read timeout*/,
			NULL /* remote authentication */,
			errbuf);
			
		if (fp != NULL){
			Sockets[n].fp = fp;
			
			addr = d->addresses;
			while (addr){
				if (addr->addr->sa_family == AF_INET){

					temp = inet_ntoa(((struct sockaddr_in *)addr->addr)->sin_addr);
				
					if (temp && lua_ValueExistsInTable(L, "IP", temp)){
						printf("%s -> %s\n", d->description == NULL ? d->name : d->description, temp);
						Sockets[n].addr = (char*)malloc(strlen(temp) + 1);
						strcpy(Sockets[n].addr,temp);
						n++;
						break;
					}
				}

				addr = addr->next;
			}

			temp = "0.0.0.0";
			Sockets[n].addr = (char*)malloc(strlen(temp) + 1);
			strcpy(Sockets[n].addr, temp);
		}
	}

	lua_newtable(L);

	for (n = 0; n < *numbsockets; n++){
		lua_pushinteger(L, Sockets[n].Socket);
		lua_pushstring(L, Sockets[n].addr);
		lua_settable(L, -3);
	}
	lua_setglobal(L, "IP");

	return Sockets;
}

SOCKET_INTERFACE * ConnectAll(lua_State*L, char * packet, int *numbsockets, int pause){

	SOCKET_INTERFACE* Sockets = NULL;
	SOCKET Current;
	int n;
	const char * lstr;
	char * listenIP = NULL;
	char host[128];
	int buffer = lua_GetGlobalInt(L, "BUFFER", 0);

	*numbsockets = 0;

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

int HasData(SOCKET_INTERFACE * socket, char * buffer, int size){

	int bytes;
	int error;
	struct pcap_pkthdr *header;
	const BYTE *pkt_data;

	if (socket == NULL)
		return SOCKET_ERROR;
	else if (socket->fp){

		error = pcap_next_ex(socket->fp, &header, &pkt_data);
		
		if (error == 1){

			if (header->len > size)
				header->len = size;
			else if (header->len <= 14)
				return 0;

			memcpy(buffer,pkt_data+14, header->len-14);

			return header->len-14;
		}
		else
			return SOCKET_ERROR;
	}
	else{
		bytes = recv(socket->Socket, buffer, size, 0);
		error;

		if (bytes < 0){

			error = WSAGetLastError();

			if (error == WSAEWOULDBLOCK)
				return 0;
			else
				return SOCKET_ERROR;
		}
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