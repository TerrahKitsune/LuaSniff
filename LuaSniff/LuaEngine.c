#include "LuaEngine.h"

void lua_PushIPHeader(lua_State*L, IPHEADER* IPH, void * trailing){

	lua_newtable(L);

	struct in_addr in;
	in.S_un.S_addr = IPH->destination_ip;

	lua_pushstring(L, "destination");
	lua_pushstring(L, inet_ntoa(in));
	lua_settable(L, -3);

	in.S_un.S_addr = IPH->source_ip;

	lua_pushstring(L, "source");
	lua_pushstring(L, inet_ntoa(in));
	lua_settable(L, -3);

	lua_pushstring(L, "checksum");
	lua_pushinteger(L, IPH->hdr_chksum);
	lua_settable(L, -3);

	lua_pushstring(L, "length");
	lua_pushinteger(L, htons(IPH->length));
	lua_settable(L, -3);

	lua_pushstring(L, "id");
	lua_pushinteger(L, IPH->packet_id);
	lua_settable(L, -3);

	lua_pushstring(L, "protocol");
	switch (IPH->protocol){
	case PROTO_TCP: lua_pushstring(L, "tcp"); break;
	case PROTO_UDP: lua_pushstring(L, "udp"); break;
	case PROTO_ICMP: lua_pushstring(L, "icmp"); break;
	default:lua_pushstring(L, "unknown"); break;
	}
	lua_settable(L, -3);

	lua_pushstring(L, "ttl");
	lua_pushinteger(L, IPH->time_to_live);
	lua_settable(L, -3);

	lua_pushstring(L, "type");
	lua_pushinteger(L, IPH->type);
	lua_settable(L, -3);

	lua_pushstring(L, "ihl");
	lua_pushinteger(L, LO_PART(IPH->ver_ihl));
	lua_settable(L, -3);

	lua_pushstring(L, "version");
	lua_pushinteger(L, HI_PART(IPH->ver_ihl));
	lua_settable(L, -3);

	lua_pushstring(L, "flags");
	lua_pushinteger(L, ((IPH->flags_foff & 0xE000) >> 13 ));
	lua_settable(L, -3);

	lua_pushstring(L, "fragment");
	lua_pushinteger(L, ((IPH->flags_foff) & 0x1FFF));
	lua_settable(L, -3);

	if (trailing){

		lua_pushstring(L, "data");

		switch (IPH->protocol){
		case PROTO_TCP: lua_PushTCP(L, trailing, htons(IPH->length) - (LO_PART(IPH->ver_ihl)*sizeof(DWORD))); break;
		case PROTO_UDP: lua_PushUDP(L, trailing, htons(IPH->length) - (LO_PART(IPH->ver_ihl)*sizeof(DWORD))); break;
		case PROTO_ICMP: lua_PushICMP(L, trailing); break;
		default:lua_pushlstring(L, trailing, htons(IPH->length) - (LO_PART(IPH->ver_ihl)*sizeof(DWORD))); break;
		}

		lua_settable(L, -3);
	}

}

void lua_PushICMP(lua_State*L, ICMPHEADER* ICMP){
	
	lua_newtable(L);

	lua_pushstring(L, "checksum");
	lua_pushinteger(L, ICMP->checksum);
	lua_settable(L, -3);

	lua_pushstring(L, "code");
	lua_pushinteger(L, ICMP->code);
	lua_settable(L, -3);

	lua_pushstring(L, "type");
	lua_pushinteger(L, ICMP->type);
	lua_settable(L, -3);

	lua_pushstring(L, "original");
	lua_PushIPHeader(L,&ICMP->original, NULL);
	lua_settable(L, -3);
}

void lua_PushUDP(lua_State*L, UDPHEADER* UDP, int len){

	BYTE * raw;
	int test;

	lua_newtable(L);

	lua_pushstring(L, "checksum");
	lua_pushinteger(L, UDP->checksum);
	lua_settable(L, -3);

	lua_pushstring(L, "cover_checksum");
	lua_pushinteger(L, UDP->conver_checksum);
	lua_settable(L, -3);

	lua_pushstring(L, "destination_port");
	lua_pushinteger(L, ntohs(UDP->destination_port));
	lua_settable(L, -3);

	lua_pushstring(L, "source_port");
	lua_pushinteger(L, ntohs(UDP->source_port));
	lua_settable(L, -3);

	test = len - sizeof(UDPHEADER);
	raw = &((BYTE*)UDP)[sizeof(UDPHEADER)];

	if (test > 0){

		lua_pushstring(L, "data");
		lua_pushlstring(L, raw, test);
		lua_settable(L, -3);
	}
	else{
		lua_pushstring(L, "data");
		lua_pushstring(L, "");
		lua_settable(L, -3);
	}
}

void lua_PushTCP(lua_State*L, TCPHEADER* TCP, int len){

	int tcp_header_size;
	BYTE * raw;
	int test;
	BYTE flags = (ntohs(TCP->info_ctrl) & 0x003F);

	lua_newtable(L);
	
	lua_pushstring(L, "ack");
	lua_pushinteger(L, TCP->ack_number);
	lua_settable(L, -3);

	lua_pushstring(L, "checksum");
	lua_pushinteger(L, TCP->checksum);
	lua_settable(L, -3);

	lua_pushstring(L, "destination_port");
	lua_pushinteger(L, ntohs(TCP->destination_port));
	lua_settable(L, -3);

	lua_pushstring(L, "seq");
	lua_pushinteger(L, TCP->seq_number);
	lua_settable(L, -3);

	lua_pushstring(L, "source_port");
	lua_pushinteger(L, ntohs(TCP->source_port));
	lua_settable(L, -3);

	lua_pushstring(L, "urgent");
	lua_pushinteger(L, TCP->urgent_pointer);
	lua_settable(L, -3);

	lua_pushstring(L, "window");
	lua_pushinteger(L, TCP->window);
	lua_settable(L, -3);

	lua_pushstring(L, "flags");
	
	//---FLAGS

	lua_newtable(L);

	lua_pushstring(L, "fin");
	lua_pushboolean(L, flags & 0x01);
	lua_settable(L, -3);

	lua_pushstring(L, "syn");
	lua_pushboolean(L, flags & 0x02);
	lua_settable(L, -3);

	lua_pushstring(L, "rst");
	lua_pushboolean(L, flags & 0x04);
	lua_settable(L, -3);

	lua_pushstring(L, "psh");
	lua_pushboolean(L, flags & 0x08);
	lua_settable(L, -3);

	lua_pushstring(L, "ack");
	lua_pushboolean(L, flags & 0x10);
	lua_settable(L, -3);

	lua_pushstring(L, "urg");
	lua_pushboolean(L, flags & 0x20);
	lua_settable(L, -3);

	//---END FLAGS

	lua_settable(L, -3);

	tcp_header_size = (ntohs(TCP->info_ctrl) & 0xF000)>>12;
	tcp_header_size *= sizeof(DWORD);

	raw = &((BYTE*)TCP)[tcp_header_size];
	test = len - tcp_header_size;

	if (test > 0){

		raw[test] = '\0';
		lua_pushstring(L, "data");
		lua_pushlstring(L, raw, test);
		lua_settable(L, -3);
	}
	else{
		lua_pushstring(L, "data");
		lua_pushstring(L, "");
		lua_settable(L, -3);
	}
}

int lua_ExecuteFile(lua_State*L, const char * file){

	if (luaL_loadfile(L, file)!=0){
		printf("LUA ERROR: %s\n", lua_tostring(L,-1));
		lua_pop(L, 1);
		return 0;
	}
	else if (lua_pcall(L, 0, 0, (void*)NULL) != 0){
		printf("LUA ERROR: %s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
		return 0;
	}
	return 1;
}

int lua_CheckFunctionExists(lua_State*L, const char * func){

	int ret;

	lua_getglobal(L, func);
	ret = (lua_type(L, -1) == LUA_TFUNCTION);
	lua_pop(L,1);

	return ret;
}

int lua_PacketRecv(lua_State*L, IPHEADER* IPH, void * trailer, const char * interf){

	//Clean stack
	lua_settop(L, 0);

	//Push global
	lua_getglobal(L, "Recv");

	//Push table
	lua_PushIPHeader(L, IPH, trailer);

	if (interf)
		lua_pushstring(L, interf);
	else
		lua_pushnil(L);

	//Call 1 argument 0 results
	if (lua_pcall(L, 2, 0,(void*)NULL) != 0){
		printf("LUA ERROR: %s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
		return 0;
	}

	return 1;
}

int lua_RunTick(lua_State*L){

	int ret=0;

	//Clean stack
	lua_settop(L, 0);

	//Push global
	lua_getglobal(L, "Tick");

	if (lua_type(L, -1) != LUA_TFUNCTION){

		lua_pop(L, 1);

		lua_pushinteger(L, 0);
		lua_setglobal(L, "TICK");

		printf("LUA ERROR: %s\n", "Function Tick() is not defined; disabling ticker");

		return 0;
	}

	//Call 1 argument 0 results
	if (lua_pcall(L, 0, 1, (void*)NULL) != 0){
		printf("LUA ERROR: %s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
		return 0;
	}
	else if (lua_gettop(L)>0){
		
		if (lua_type(L, -1) == LUA_TBOOLEAN)
			ret = lua_toboolean(L, -1);
		else if (lua_type(L, -1) == LUA_TNUMBER)
			ret = lua_tointeger(L, -1) > 0;

		lua_pop(L, 1);
	}


	return ret;
}

int lua_GetGlobalString(lua_State*L, const char * name, char * buffer, unsigned int buffersize) {

	unsigned int size = buffersize;
	const char * data;
	lua_getglobal(L, name);
	if (lua_type(L, -1) != LUA_TSTRING){
		lua_pop(L, 1);
		return 0;
	}

	data = lua_tostring(L, -1);

	if (strlen(data) < size)
		size = strlen(data);

	memset(buffer, 0, buffersize);
	memcpy(buffer, data, buffersize);

	lua_pop(L, 1);

	return 1;
}

int lua_GetGlobalBoolean(lua_State*L, const char * name) {

	int ret;

	lua_getglobal(L, name);
	if (lua_type(L, -1) != LUA_TBOOLEAN){
		lua_pop(L, 1);
		return 0;
	}

	ret = lua_toboolean(L, 1);

	lua_pop(L, 1);

	return ret;
}

int lua_GetGlobalInt(lua_State*L, const char * name,int rdefault){

	int ret;

	lua_getglobal(L, name);
	if (lua_type(L, -1) != LUA_TNUMBER){
		lua_pop(L, 1);
		return rdefault;
	}

	ret = (int)lua_tonumber(L, 1);

	lua_pop(L, 1);

	return ret;
}

void lua_SetGlobalString(lua_State*L, const char * name, const char * str){
	
	lua_pushstring(L, str);
	lua_setglobal(L, name);
}