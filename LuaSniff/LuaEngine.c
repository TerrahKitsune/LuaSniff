#include "Network.h"

void LoadLibs(lua_State*L){

	lua_pushcfunction(L, L_cls);
	lua_setglobal(L, "cls");

	lua_pushcfunction(L, L_GetTextColor);
	lua_setglobal(L, "GetTextColor");

	lua_pushcfunction(L, L_SetTextColor);
	lua_setglobal(L, "SetTextColor");

	lua_pushcfunction(L, L_getch);
	lua_setglobal(L, "GetChar");

	lua_pushcfunction(L, L_kbhit);
	lua_setglobal(L, "HasKeyDown");

	lua_pushcfunction(L, stackDump);
	lua_setglobal(L, "DumpStack");
}

void stackDump(lua_State *L) {
	int i = lua_gettop(L);
	printf(" ----------------  Stack Dump ----------------\n");
	while (i) {
		int t = lua_type(L, i);
		switch (t) {
		case LUA_TSTRING:
			printf("%d:`%s'\n", i, lua_tostring(L, i));
			break;
		case LUA_TBOOLEAN:
			printf("%d: %s\n", i, lua_toboolean(L, i) ? "true" : "false");
			break;
		case LUA_TNUMBER:
			printf("%d: %g\n", i, lua_tonumber(L, i));
			break;
		default: printf("%d: %s\n", i, lua_typename(L, t)); break;
		}
		i--;
	}
	printf("--------------- Stack Dump Finished ---------------");
}

static int L_kbhit(lua_State *L){

	lua_pushboolean(L, _kbhit());
	return 1;
}

static int L_getch(lua_State *L){
	lua_pushinteger(L, _getch());
	return 1;
}

static int L_GetTextColor(lua_State *L){

	WORD data;
	CONSOLE_SCREEN_BUFFER_INFO   csbi;
	if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)){
		data = csbi.wAttributes;

		lua_pushinteger(L, HI_PART(data));
		lua_pushinteger(L, LO_PART(data));
	}
	else{
		lua_pushnil(L);
		lua_pushnil(L);
	}

	return 2;
}

static int L_SetTextColor(lua_State *L){

	int BackC = luaL_checknumber(L, 1);
	int ForgC = luaL_checknumber(L, 2);

	lua_pop(L, 2);

	WORD wColor = ((BackC & 0x0F) << 4) + (ForgC & 0x0F);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), wColor);

	return 0;
}

static int L_cls(lua_State *L) {

	HANDLE                     hStdOut;
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	DWORD                      count;
	DWORD                      cellCount;
	COORD                      homeCoords = { 0, 0 };

	hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hStdOut == INVALID_HANDLE_VALUE) return 0;

	if (!GetConsoleScreenBufferInfo(hStdOut, &csbi)) return 0;
	cellCount = csbi.dwSize.X *csbi.dwSize.Y;

	if (!FillConsoleOutputCharacter(
		hStdOut,
		(TCHAR) ' ',
		cellCount,
		homeCoords,
		&count
		)) return 0;

	if (!FillConsoleOutputAttribute(
		hStdOut,
		csbi.wAttributes,
		cellCount,
		homeCoords,
		&count
		)) return 0;

	SetConsoleCursorPosition(hStdOut, homeCoords);

	return 0; 
}

void lua_PushIPv6Address(lua_State*L, BYTE * raw) {

	char buffer[128];
	/*char octet[8];
	int n;

	buffer[0] = 0;

	for (n = 0; n < 8; n++) {
		if (n < 7)
			sprintf(octet, "%02X%02X:", raw[(n * 2)], raw[(n * 2) + 1]);
		else 
			sprintf(octet, "%02X%02X", raw[(n * 2)], raw[(n * 2) + 1]);
		strcat(buffer, octet);
	}*/


	InetNtop(AF_INET6, raw, buffer, 127);

	lua_pushstring(L, buffer);
}

DWORD GetBits(DWORD original, int start, int len) {

	int end = start + len;
	DWORD mask = (1 << (end - start)) - 1;
	return (original >> start) & mask;
}

void lua_PushProtocolName(lua_State*L, int type){

	switch (type){
	case 0:lua_pushstring(L,"hopopt"); break;
	case 1:lua_pushstring(L, "icmp"); break;
	case 2:lua_pushstring(L, "igmp"); break;
	case 3:lua_pushstring(L, "ggp"); break;
	case 4:lua_pushstring(L, "ip-in-ip"); break;
	case 5:lua_pushstring(L, "st"); break;
	case 6:lua_pushstring(L, "tcp"); break;
	case 7:lua_pushstring(L, "cbt"); break;
	case 8:lua_pushstring(L, "egp"); break;
	case 9:lua_pushstring(L, "igp"); break;
	case 10:lua_pushstring(L, "bbn-rcc-mon"); break;
	case 11:lua_pushstring(L, "nvp-ii"); break;
	case 12:lua_pushstring(L, "pup"); break;
	case 13:lua_pushstring(L, "argus"); break;
	case 14:lua_pushstring(L, "emcon"); break;
	case 15:lua_pushstring(L, "xnet"); break;
	case 16:lua_pushstring(L, "chaos"); break;
	case 17:lua_pushstring(L, "udp"); break;
	case 18:lua_pushstring(L, "mux"); break;
	case 19:lua_pushstring(L, "dcn-meas"); break;
	case 20:lua_pushstring(L, "hmp"); break;
	case 21:lua_pushstring(L, "prm"); break;
	case 22:lua_pushstring(L, "xns-idp"); break;
	case 23:lua_pushstring(L, "truck-1"); break;
	case 24:lua_pushstring(L, "trunk-2"); break;
	case 25:lua_pushstring(L, "leal-1"); break;
	case 26:lua_pushstring(L, "leaf-2"); break;
	case 27:lua_pushstring(L, "rdp"); break;
	case 28:lua_pushstring(L, "irtp"); break;
	case 29:lua_pushstring(L, "iso-tp4"); break;
	case 30:lua_pushstring(L, "netblt"); break;
	case 31:lua_pushstring(L, "mfe-nsp"); break;
	case 32:lua_pushstring(L, "merit-inp"); break;
	case 33:lua_pushstring(L, "dccp"); break;
	case 34:lua_pushstring(L, "3cp"); break;
	case 35:lua_pushstring(L, "idpr"); break;
	case 36:lua_pushstring(L, "xtp"); break;
	case 37:lua_pushstring(L, "ddp"); break;
	case 38:lua_pushstring(L, "idpr-cmtp"); break;
	case 39:lua_pushstring(L, "tp++"); break;
	case 40:lua_pushstring(L, "il"); break;
	case 41:lua_pushstring(L, "ipv6"); break;
	case 42:lua_pushstring(L, "sdrp"); break;
	case 43:lua_pushstring(L, "ipv6-route"); break;
	case 44:lua_pushstring(L, "ipv6-frag"); break;
	case 45:lua_pushstring(L, "idrp"); break;
	case 46:lua_pushstring(L, "rsvp"); break;
	case 47:lua_pushstring(L, "gre"); break;
	case 48:lua_pushstring(L, "mhrp"); break;
	case 49:lua_pushstring(L, "bna"); break;
	case 50:lua_pushstring(L, "esp"); break;
	case 51:lua_pushstring(L, "ah"); break;
	case 52:lua_pushstring(L, "i-nlsp"); break;
	case 53:lua_pushstring(L, "swipe"); break;
	case 54:lua_pushstring(L, "narp"); break;
	case 55:lua_pushstring(L, "mobile"); break;
	case 56:lua_pushstring(L, "tlsp"); break;
	case 57:lua_pushstring(L, "skip"); break;
	case 58:lua_pushstring(L, "ipv6-icmp"); break;
	case 59:lua_pushstring(L, "ipv6-nonxt"); break;
	case 60:lua_pushstring(L, "ipv6-opts"); break;
	case 61:lua_pushstring(L, "any-inp"); break;
	case 62:lua_pushstring(L, "cftp"); break;
	case 63:lua_pushstring(L, "any-ln"); break;
	case 64:lua_pushstring(L, "sat-expak"); break;
	case 65:lua_pushstring(L, "kryptolan"); break;
	case 66:lua_pushstring(L, "rvd"); break;
	case 67:lua_pushstring(L, "ippc"); break;
	case 68:lua_pushstring(L, "any-dfs"); break;
	case 69:lua_pushstring(L, "sat-mon"); break;
	case 70:lua_pushstring(L, "visa"); break;
	case 71:lua_pushstring(L, "ipcu"); break;
	case 72:lua_pushstring(L, "cpnx"); break;
	case 73:lua_pushstring(L, "cphb"); break;
	case 74:lua_pushstring(L, "wsn"); break;
	case 75:lua_pushstring(L, "pvp"); break;
	case 76:lua_pushstring(L, "br-sat-mon"); break;
	case 77:lua_pushstring(L, "sun-nd"); break;
	case 78:lua_pushstring(L, "wb-mon"); break;
	case 79:lua_pushstring(L, "wb-expak"); break;
	case 80:lua_pushstring(L, "iso-ip"); break;
	case 81:lua_pushstring(L, "vmtp"); break;
	case 82:lua_pushstring(L, "secure-vmtp"); break;
	case 83:lua_pushstring(L, "vines"); break;
	case 84:lua_pushstring(L, "ttp"); break;
	case 85:lua_pushstring(L, "nsfnet-igp"); break;
	case 86:lua_pushstring(L, "dgp"); break;
	case 87:lua_pushstring(L, "tcf"); break;
	case 88:lua_pushstring(L, "eigrp"); break;
	case 89:lua_pushstring(L, "ospf"); break;
	case 90:lua_pushstring(L, "sprite-rpc"); break;
	case 91:lua_pushstring(L, "larp"); break;
	case 92:lua_pushstring(L, "mtp"); break;
	case 93:lua_pushstring(L, "ax.25"); break;
	case 94:lua_pushstring(L, "ipip"); break;
	case 95:lua_pushstring(L, "micp"); break;
	case 96:lua_pushstring(L, "scc-sp"); break;
	case 97:lua_pushstring(L, "etherip"); break;
	case 98:lua_pushstring(L, "encap"); break;
	case 99:lua_pushstring(L, "any-private"); break;
	case 100:lua_pushstring(L, "gmtp"); break;
	case 101:lua_pushstring(L, "ifmp"); break;
	case 102:lua_pushstring(L, "pnni"); break;
	case 103:lua_pushstring(L, "pim"); break;
	case 104:lua_pushstring(L, "aris"); break;
	case 105:lua_pushstring(L, "scps"); break;
	case 106:lua_pushstring(L, "qnx"); break;
	case 107:lua_pushstring(L, "a/n"); break;
	case 108:lua_pushstring(L, "ipcomp"); break;
	case 109:lua_pushstring(L, "snp"); break;
	case 110:lua_pushstring(L, "compaq-peer"); break;
	case 111:lua_pushstring(L, "ipx-in-ip"); break;
	case 112:lua_pushstring(L, "vrrp"); break;
	case 113:lua_pushstring(L, "pgm"); break;
	case 114:lua_pushstring(L, "any-0hop"); break;
	case 115:lua_pushstring(L, "l2tp"); break;
	case 116:lua_pushstring(L, "ddx"); break;
	case 117:lua_pushstring(L, "iatp"); break;
	case 118:lua_pushstring(L, "stp"); break;
	case 119:lua_pushstring(L, "iplt"); break;
	case 120:lua_pushstring(L, "uti"); break;
	case 121:lua_pushstring(L, "smp"); break;
	case 122:lua_pushstring(L, "sm"); break;
	case 123:lua_pushstring(L, "ptp"); break;
	case 124:lua_pushstring(L, "is-isoveripv4"); break;
	case 125:lua_pushstring(L, "fire"); break;
	case 126:lua_pushstring(L, "crtp"); break;
	case 127:lua_pushstring(L, "crudp"); break;
	case 128:lua_pushstring(L, "sscompmce"); break;
	case 129:lua_pushstring(L, "iplt"); break;
	case 130:lua_pushstring(L, "sps"); break;
	case 131:lua_pushstring(L, "pipe"); break;
	case 132:lua_pushstring(L, "sctp"); break;
	case 133:lua_pushstring(L, "fc"); break;
	case 134:lua_pushstring(L, "rsvp-e2e-ignore"); break;
	case 135:lua_pushstring(L, "mobilityheader"); break;
	case 136:lua_pushstring(L, "udplite"); break;
	case 137:lua_pushstring(L, "mpls-in-ip"); break;
	case 138:lua_pushstring(L, "manet"); break;
	case 139:lua_pushstring(L, "hip"); break;
	case 140:lua_pushstring(L, "shim6"); break;
	case 141:lua_pushstring(L, "wesp"); break;
	case 142:lua_pushstring(L, "rohc"); break;
	case 253:lua_pushstring(L, "testing/experimentation"); break;
	case 254:lua_pushstring(L, "testing/experimentation"); break;
	case 255:lua_pushstring(L, "reserved"); break;
	default:lua_pushfstring(L, "unassigned (%d)", type); break;
	}
}

void lua_PushHopByHop(lua_State*L, HOP_BY_HOP* hbh,int len){

	lua_newtable(L);

	lua_pushstring(L, "length");
	lua_pushinteger(L, hbh->hdr_ext_len);
	lua_settable(L, -3);

	lua_pushstring(L, "options");
	lua_pushlstring(L, hbh->options, hbh->hdr_ext_len > 14 ? 14 : hbh->hdr_ext_len);
	lua_settable(L, -3);

	lua_pushstring(L, "protocol");
	lua_PushProtocolName(L, hbh->next_header);
	lua_settable(L, -3);

	lua_pushstring(L, "data");
	lua_PushIPv6AdditionalHeader(L, (hbh + sizeof(HOP_BY_HOP)), hbh->next_header, len - sizeof(HOP_BY_HOP));
	lua_settable(L, -3);
}

void lua_PushRouting(lua_State*L, IPV6_ROUTING* routing, int len){

	lua_newtable(L);

	lua_pushstring(L, "length");
	lua_pushinteger(L, routing->hdr_ext_len);
	lua_settable(L, -3);

	lua_pushstring(L, "options");
	lua_pushlstring(L, routing->data, routing->hdr_ext_len > 14 ? 14 : routing->hdr_ext_len);
	lua_settable(L, -3);

	lua_pushstring(L, "routing_type");
	lua_pushinteger(L, routing->routing_type);
	lua_settable(L, -3);

	lua_pushstring(L, "segments_left");
	lua_pushinteger(L, routing->segments_left);
	lua_settable(L, -3);

	lua_pushstring(L, "protocol");
	lua_PushProtocolName(L, routing->next_header);
	lua_settable(L, -3);

	lua_pushstring(L, "data");
	lua_PushIPv6AdditionalHeader(L, (routing + sizeof(IPV6_ROUTING)), routing->next_header, len - sizeof(IPV6_ROUTING));
	lua_settable(L, -3);
}

void lua_PushIPV6Frament(lua_State*L, IPV6_FRAGMENT* fragment, int len){

	lua_newtable(L);

	lua_pushstring(L, "identification");
	lua_pushinteger(L, fragment->identification);
	lua_settable(L, -3);

	fragment->fragmentoffset_res_m = ntohs(fragment->fragmentoffset_res_m);

	lua_pushstring(L, "fragment_offset");
	lua_pushinteger(L, GetBits(fragment->fragmentoffset_res_m, 1, 13));
	lua_settable(L, -3);

	lua_pushstring(L, "res");
	lua_pushinteger(L, GetBits(fragment->fragmentoffset_res_m, 13, 2));
	lua_settable(L, -3);

	lua_pushstring(L, "m");
	lua_pushboolean(L, GetBits(fragment->fragmentoffset_res_m, 15, 1));
	lua_settable(L, -3);

	lua_pushstring(L, "protocol");
	lua_PushProtocolName(L, fragment->next_header);
	lua_settable(L, -3);

	lua_pushstring(L, "data");
	lua_PushIPv6AdditionalHeader(L, (fragment + sizeof(IPV6_FRAGMENT)), fragment->next_header, len - sizeof(IPV6_FRAGMENT));
	lua_settable(L, -3);
}

void lua_PushIPv6AdditionalHeader(lua_State*L, void * start, int type, WORD len) {

	//Something is fucked, push nil
	if (len <= 0){
		lua_pushnil(L);
		return;
	}

	switch (type){
	case PROTO_TCP: lua_PushTCP(L, start, len); break;
	case PROTO_UDP: lua_PushUDP(L, start, len); break;
	case PROTO_ICMP: lua_PushICMP(L, start); break;
	case 58:lua_PushIPV6ICMP(L, start); break;
	case 43:lua_PushRouting(L, start, len); break;
	case 0:lua_PushHopByHop(L, start, len); break;
	case 44:lua_PushIPV6Frament(L, start, len); break;
	default:lua_pushlstring(L, start, len); break;
	}
}

void lua_PushIPV6ICMP(lua_State*L, IPV6ICMPHEADER* ICMP){

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
}

void lua_PushIPv6Header(lua_State*L, IPV6HEADER* IPH, void * trailing, int reallen) {

	WORD len = htons(IPH->length);

	lua_newtable(L);

	lua_pushstring(L, "version");
	lua_pushinteger(L, 6);
	lua_settable(L, -3);

	lua_pushstring(L, "destination");
	lua_PushIPv6Address(L,IPH->destination_ip);
	lua_settable(L, -3);

	lua_pushstring(L, "source");
	lua_PushIPv6Address(L, IPH->source_ip);
	lua_settable(L, -3);

	lua_pushstring(L, "length");
	lua_pushinteger(L, len);
	lua_settable(L, -3);

	IPH->ver_tc_fl = ntohl(IPH->ver_tc_fl);

	lua_pushstring(L, "version");
	lua_pushinteger(L, GetBits(IPH->ver_tc_fl,28,4));
	lua_settable(L, -3);

	lua_pushstring(L, "trafficclass");
	lua_pushinteger(L, GetBits(IPH->ver_tc_fl, 20, 8));
	lua_settable(L, -3);

	lua_pushstring(L, "flowlabel");
	lua_pushinteger(L, GetBits(IPH->ver_tc_fl, 1, 20));
	lua_settable(L, -3);

	lua_pushstring(L, "ttl");
	lua_pushinteger(L, IPH->hop_limit);
	lua_settable(L, -3);

	lua_pushstring(L, "protocol");
	lua_PushProtocolName(L, IPH->next_header);
	lua_settable(L, -3);

	if (len <= 0)
		len = (WORD)reallen - sizeof(IPV6HEADER);

	lua_pushstring(L, "data");
	lua_PushIPv6AdditionalHeader(L, trailing, IPH->next_header, len);
	lua_settable(L, -3);
	
}

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
	lua_PushProtocolName(L, IPH->protocol);
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

int lua_IPv4PacketRecv(lua_State*L, IPHEADER* IPH, void * trailer, const char * interf){

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

int lua_IPv6PacketRecv(lua_State*L, IPV6HEADER* IPH, void * trailer, const char * interf, int reallen) {

	//Clean stack
	lua_settop(L, 0);

	//Push global
	lua_getglobal(L, "Recv");

	//Push table
	lua_PushIPv6Header(L, IPH, trailer, reallen);

	if (interf)
		lua_pushstring(L, interf);
	else
		lua_pushnil(L);

	//Call 1 argument 0 results
	if (lua_pcall(L, 2, 0, (void*)NULL) != 0) {
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

	const char * data;
	lua_getglobal(L, name);
	if (lua_type(L, -1) != LUA_TSTRING){
		lua_pop(L, 1);
		return 0;
	}

	unsigned int size=0;
	data = lua_tolstring(L, -1,&size);

	memset(buffer, 0, buffersize);

	if (size>0 && size<buffersize)
		memcpy(buffer, data, size);

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

int lua_ValueExistsInTable(lua_State*L, const char * table, const char * value){

	int ret =0;
	const char * temp;

	if(table)
		lua_getglobal(L, table);

	if (lua_type(L, -1) == LUA_TTABLE){

		lua_pushnil(L);
		
		while (lua_next(L, -2)){

			if (lua_isstring(L, -1)){

				temp = lua_tostring(L, -1);

				if (temp && strcmp(temp, value) == 0){
					ret = 1;
					lua_pop(L, 2);
					break;
				}
			}
			else if (lua_istable(L,-1)) {

				if (lua_ValueExistsInTable(L,NULL, value)) {
					ret = 1;
					lua_pop(L, 1);
					break;
				}				
			}
			lua_pop(L, 1);
		}
	}
	else if (lua_type(L, -1) == LUA_TSTRING){	
		temp = lua_tostring(L, -1);
		if (!temp)
			ret = 0;
		else
			ret = strcmp(temp, value) == 0;
	}

	lua_pop(L, 1);	
	return ret;
}