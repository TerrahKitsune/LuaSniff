#pragma warning( disable: 4024 ) //Don' warn me about formal parameters
#pragma warning( disable: 4047 ) //Don't warn me about indirectio

//build it as a dll
#define LUA_BUILD_AS_DLL
//then embed the dll directly
#define LUA_CORE

#include "lua\lua.h"
#include "lua\lauxlib.h"
#include "lua\lualib.h"

#include <conio.h>

#include "IPHeader.h"

static int L_GetTextColor(lua_State *L);
static int L_SetTextColor(lua_State *L);
static int L_cls(lua_State *L);
static int L_getch(lua_State *L);
static int L_kbhit(lua_State *L);

void LoadLibs(lua_State*L);

//Push a IPH as a lua table unto the lua stack
//if trailing isnt null then it'll push it on as a tcp/udp/icmp/unknown in the table
void lua_PushIPHeader(lua_State*L, IPHEADER* IPH, void * trailing);

//Push a ICMP packet onto the stack
void lua_PushICMP(lua_State*L, ICMPHEADER* ICMP);

//Push a TCP packet onto the stack
void lua_PushTCP(lua_State*L, TCPHEADER* TCP, int len);

//Push a UDP packet onto the stack
void lua_PushUDP(lua_State*L, UDPHEADER* UDP, int len);

//Executes a file, prints error message if any
//Returns 1 on success
int lua_ExecuteFile(lua_State*L, const char * file);

//Returns 1 if a function by the name exists in the global table
int lua_CheckFunctionExists(lua_State*L, const char * func);

//Run the packet recived event
int lua_IPv4PacketRecv(lua_State*L, IPHEADER* IPH, void * trailer, const char * interf);

//Run the packet recived event
int lua_IPv6PacketRecv(lua_State*L, IPV6HEADER* IPH, void * trailer, const char * interf);

//Fill a buffer with data from the lua engine
int lua_GetGlobalString(lua_State*L, const char * name, char * buffer, unsigned int buffersize);

//Get a global bool, default to 0(false)
int lua_GetGlobalBoolean(lua_State*L, const char * name);

//Get a global bool, default to 0(false)
int lua_GetGlobalInt(lua_State*L, const char * name, int rdefault);

//Set a global string in the lua environment
void lua_SetGlobalString(lua_State*L, const char * name, const char * str);

//Procs the tick event
int lua_RunTick(lua_State*L);

int lua_ValueExistsInTable(lua_State*L, const char * table, const char * value);