#include "Network.h"

void LoadNetLibs(lua_State *L){
	lua_pushcfunction(L, L_Resolve);
	lua_setglobal(L, "DNS");

	lua_pushcfunction(L, L_GetOwnHost);
	lua_setglobal(L, "GetHostName");

	lua_pushcfunction(L, L_ReverseDNS);
	lua_setglobal(L, "ReverseDNS");
}

static int L_ReverseDNS(lua_State *L){

	luaL_checkstring(L, 1);

	size_t len;
	const char * addr = luaL_tolstring(L, 1, &len);
	char * resolveaddr = (char*)malloc(len+1);

	resolveaddr[len] = '\0';
	memcpy(resolveaddr, addr, len);
	lua_pop(L,1);

	struct sockaddr_in ip4addr;
	memset(&ip4addr, 0, sizeof(struct sockaddr_in));
	ip4addr.sin_family = AF_INET;
	ip4addr.sin_port = htons(0);
	inet_pton(AF_INET, resolveaddr, &ip4addr.sin_addr);

	char host[NI_MAXHOST], service[NI_MAXSERV];
	if (getnameinfo((struct sockaddr *) &ip4addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV) == 0)
	{
		lua_pushstring(L,host);
	}
	else{
		lua_pushnil(L);
	}

	free(resolveaddr);

	return 1;
}

static int L_Resolve(lua_State *L) {

	size_t len;
	const char * addr = luaL_tolstring(L, 1, &len);
	char * ip = ResolveIP(addr,L);

	lua_pop(L, 1);

	if (ip){
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

void ResolveIPTable(lua_State*L) {

	int n = 0;
	const char * temp;
	char host[128];
	char * str;
	char ** resolvecache;
	int cachesize = 0;
	char * cursor;
	size_t strsize;

	lua_getglobal(L, "IP");
	if (lua_type(L, -1) == LUA_TTABLE) {

		lua_pushnil(L);

		while (lua_next(L, -2)) {
			if (lua_isstring(L, -1)) {
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
		while (lua_next(L, -2)) {
			if (lua_isstring(L, -1)) {
				temp = lua_tolstring(L, -1, &strsize);
				if (temp) {
					resolvecache[n] = calloc(1, strsize + 1);
					strcpy(resolvecache[n], temp);
				}
				n++;
			}
			lua_pop(L, 1);
		}
		lua_pop(L, 1);

		lua_newtable(L);

		for (n = 0; n < cachesize; n++) {
			if (resolvecache[n]) {
				cursor = ResolveIP(resolvecache[n], L);
				if (cursor) {
					lua_rawseti(L, -2, n + 1);
					free(cursor);
					cursor = NULL;
				}
			}
		}
		lua_setglobal(L, "IP");

		for (n = 0; n < cachesize; n++) {
			if (resolvecache[n])
				free(resolvecache[n]);
		}

		free(resolvecache);
	}

	else if (lua_type(L, -1) == LUA_TSTRING) {
		const char * ip = lua_tostring(L, -1);
		lua_pop(L, 1);
		str = ResolveIP(ip, L);
		if (str) {
			lua_setglobal(L, "IP");
			free(str);
		}
		else
		{
			lua_pop(L, 1);
			gethostname(host, 127);
			str = ResolveIP(host, L);
			if (str) {

				lua_setglobal(L, "IP");
				free(str);
			}
		}
	}
	else {
		lua_pop(L, 1);
		gethostname(host, 127);
		str = ResolveIP(host, NULL);
		if (str) {

			lua_SetGlobalString(L, "IP", str);
			free(str);
		}
	}
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
	int cachesize = 0;
	int wasadded = 0;
	char host[128];

	if (buffer < 1500)
		buffer = 1500;

	for (d = alldevs; d; d = d->next)(*numbsockets)++;

	if (*numbsockets <= 0)
		return NULL;

	Sockets = (SOCKET_INTERFACE*)calloc(*numbsockets, sizeof(SOCKET_INTERFACE));

	(*numbsockets) = 0;
	n = 0;
	for (d = alldevs; d; d = d->next){

		wasadded = 0;

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

					InetNtop(AF_INET, &addr->addr->sa_data[2], host, 128);

					temp = host;

					if (temp){
						printf("%s -> %s\n", d->description == NULL ? d->name : d->description, temp);
						Sockets[n].addr = (char*)malloc(strlen(temp) + 1);
						strcpy(Sockets[n].addr,temp);					
					}

					if (lua_ValueExistsInTable(L, "IP", temp))
						wasadded = 1;
				}
				else if (addr->addr->sa_family == AF_INET6) {

					InetNtop(AF_INET6, &addr->addr->sa_data[6], host, 128);

					temp = host;

					if (temp) {
						printf("%s -> %s\n", d->description == NULL ? d->name : d->description, temp);
						Sockets[n].addrv6 = (char*)malloc(strlen(temp) + 1);
						strcpy(Sockets[n].addrv6, temp);						
					}

					if(lua_ValueExistsInTable(L, "IP", temp))
						wasadded = 1;
				}

				addr = addr->next;
			}

			if (!wasadded){
				pcap_close(fp);
			}
			else {
				n++;
				(*numbsockets)++;
			}
		}
	}

	return Sockets;
}

char * FormatErrorMessage(int error,BOOL print){

	LPTSTR * Error=NULL;

	if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		error,
		0,
		(LPTSTR)&Error,
		0,
		NULL) == 0)
	{
		if (Error)
			LocalFree(Error);

		if (print)puts("failed to translate error");
	}

	if (!Error){
		
		if (print)puts("no error message found");

		return NULL;
	}
	else{

		if (print){
			puts(Error);
			LocalFree(Error);
			return NULL;
		}
		else{

			char * buf = (char*)malloc(strlen(Error)+1);
			strcpy(buf, Error);
			return buf;
		}
	}
}

SOCKET_INTERFACE * ConnectAll(lua_State*L, char * packet, int *numbsockets, int pause){

	SOCKET_INTERFACE* Sockets = NULL;
	SOCKET Current;
	int n;
	const char * lstr;
	char * listenIP = NULL;
	char host[128];
	int buffer = lua_GetGlobalInt(L, "BUFFER", 0);
	const char * temp;
	size_t len;

	*numbsockets = 0;

	lua_getglobal(L, "IP");
	if (lua_type(L, -1) == LUA_TTABLE){

		lua_pushnil(L);

		while (lua_next(L, -2)){
			if (lua_isstring(L, -1)){
				(*numbsockets)++;
			}
			else if(lua_istable(L,-1)){
				
				lua_pushnil(L);
				while (lua_next(L, -2)){

					if (lua_isstring(L, -1)){
						(*numbsockets)++;
					}

					lua_pop(L, 1);
				}
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
				temp = lua_tolstring(L, -1, &len);
				if (temp&&len > 0){
					Sockets[n].addr = (char*)calloc(len + 1, 1);
					strcpy(Sockets[n].addr, temp);
					n++;
				}
			}
			else if (lua_istable(L, -1)){

				lua_pushnil(L);
				while (lua_next(L, -2)){

					if (lua_isstring(L, -1)){
						temp = lua_tolstring(L, -1, &len);
						if (temp&&len > 0){

							memset(&Sockets[n], NULL, sizeof(SOCKET_INTERFACE));

							if (strstr(temp, ":")){
								Sockets[n].addrv6 = (char*)calloc(len + 1, 1);
								strcpy(Sockets[n].addrv6, temp);
								Sockets[n].Socket = OpenReadAllSocket(Sockets[n].addrv6, buffer);
							}
							else{
								Sockets[n].addr = (char*)calloc(len + 1, 1);
								strcpy(Sockets[n].addr, temp);
								Sockets[n].Socket = OpenReadAllSocket(Sockets[n].addr, buffer);
							}

							if (Sockets[n].Socket == SOCKET_ERROR){
								FormatErrorMessage(WSAGetLastError(), TRUE);
								if (pause)
									_getch();
							}
							else{
								if (Sockets[n].addr)
									printf("Connected: %s\n", Sockets[n].addr);
								else if (Sockets[n].addrv6)
									printf("Connected: %s\n", Sockets[n].addrv6);
							}

							n++;
						}
					}

					lua_pop(L, 1);
				}
			}
			lua_pop(L, 1);
		}			
	}

	lua_pop(L, 3);

	return Sockets;
}

SOCKET OpenReadAllSocket(const char * addr, int socketbuffersize){

	SOCKET				listen_socket = -1;
	struct sockaddr_in	socketdata;
	int					opt = 1;
	DWORD				dwLen = 0;
	unsigned long		ul = 1;
	struct sockaddr_in6 socket_struct;

	if (strstr(addr, ":")){

		listen_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_IPV6);

		if (listen_socket == SOCKET_ERROR)
		{
			return SOCKET_ERROR;
		}
	
		socket_struct.sin6_family = AF_INET6;
		inet_pton(AF_INET6, addr, (void *)&socket_struct.sin6_addr.s6_addr);
		socket_struct.sin6_port = htons(0);
		socket_struct.sin6_scope_id = 0;

		if (bind(listen_socket, (struct sockaddr *)&socket_struct, sizeof(socket_struct)) == SOCKET_ERROR)
		{
			return SOCKET_ERROR;
		}
	}
	else{

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
			return SOCKET_ERROR;
		}
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
		return SOCKET_ERROR;
	}

	return listen_socket;
}

char * ResolveIP(const char * ip, lua_State*L)
{
	char				host[128];
	char				first[128];
	ADDRINFO			*result;
	int					resultcode;
	struct addrinfo		*ptr = NULL;
	char				*ret = NULL;
	int					size;

	if (ip == NULL || strlen(ip) <= 0){

		host[127] = 0;
		gethostname(host, 127);
		resultcode = getaddrinfo(host, NULL, NULL, &result);
	}
	else
		resultcode = getaddrinfo(ip, NULL, NULL, &result);

	if (resultcode != 0){

		printf("ResolveIP() Error: %d\n", resultcode);
		return NULL;
	}

	if (L)
		lua_newtable(L);

	int n = 0;
	//Loop the results
	first[0] = '\0';	
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next){

		//Take the first ip4 we find
		if (ptr->ai_family == AF_INET){
			if (first[0] == 0) {
				InetNtop(AF_INET, &((struct sockaddr_in *) ptr->ai_addr)->sin_addr, first, 128);
				host[0] = '\0';
				strcpy(host,first);
			}
			else {
				host[0] = '\0';
				InetNtop(AF_INET, &((struct sockaddr_in *) ptr->ai_addr)->sin_addr, host, 128);
			}
			if(!L)
				break;
			else {
				lua_pushstring(L, host);
				lua_rawseti(L, -2, ++n);
			}
		}
		else if(ptr->ai_family == AF_INET6 && L){
			host[0] = '\0';
			InetNtop(AF_INET6, &((struct sockaddr_in6 *) ptr->ai_addr)->sin6_addr, host, 128);
			lua_pushstring(L, host);
			lua_rawseti(L, -2, ++n);
		}
	}

	freeaddrinfo(result);

	if (first[0] == '\0'){
		printf("ResolveIP() Error: found no ip4 or ip6 address\n");
		return NULL;
	}

	size = strlen(first) + 1;
	ret = malloc(size);
	memset(ret, 0, size);

	strcpy(ret, first);

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