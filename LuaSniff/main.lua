--[[Packet fields (IP Header IPV6):
string destination
string source
int length
string protocol (tcp,udp,icmp,unkown)
int ttl
int trafficclass
int flowlabel
int version
table/string/nil data (if unknown this is a string)
]]

--[[IPV6ICMP Data fields:

int checksum
int code
int type

]]

--[[IPV6 Routing Data fields:

int length
string options
int routing_type
int segments_left
string protocol
table/string/nil data (if unknown this is a string)

]]

--[[IPV6 HOP BY HOP Data fields:

int length
string options
string protocol
table/string/nil data (if unknown this is a string)

]]

--[[IPV6 Fragment Data fields:

int identification
int res
bool m (true on the last fragment)
string protocol
table/string/nil data (if unknown this is a string)

]]

--[[Packet fields (IP Header):
string destination
string source
int checksum
int length
int id
string protocol (tcp,udp,icmp,unkown)
int ttl
int type
int ihl (ip header length)
int version
int flags
int fragment
table/string/nil data (if unknown this is a string)
]]

--[[ICMP Data fields:

https://tools.ietf.org/html/rfc777

int checksum
int code
int type (0=reply,3=unreachable,8=request,11=timeout)
table original (contains the original stripped IP header)

]]

--[[TCP Data fields:

int ack
int checksum
int destination_port
int seq
int source_port
int urgent
int window
table flags (array of bools keys: urg,ack,psh,rst,syn,fin)
string data

]]

--[[UDP Data fields:

int checksum
int conver_checksum
int destination_port
int source_port
string data

]]

--[[Custom functions:
void cls() -> clears the screen
string dns(address) -> resolves a dns address



]]
--IP if its a table it'll attempt listening to the interfaces (adapters)
--with their respective IP
IP = {};
IP[0] = "localhost";
IP[1] = GetHostName();

--IP can also be a single address
--IP="127.0.0.1";

--IP can also be nil, then it'll listen to the first non loopback interface
--IP=nil;

--After the initial script IP will be replaced by the actual active interfaces
--Table if a table was provided, string otherwise

--If this is true then the program will wait for user input on failure
PAUSE=true;

--Time in miliseconds between the Tick function is proc-ed (Tick())
TICK=500;

--If this is set it'll modify the socket-buffer to a new size
--this is usable if you got high traffic on your socket
--increase if your CPU is too shit to handle the amount of data you're reciving
--Default: 8192
BUFFER=8192;

--This is the title of the console window, it'll update if changed
TITLE="Sniffer"

--If this is true then duplicate data (with pcap and winsock)
--will be ignored,ie; not pushed to the lua environment
NODUP=true;

--If true then the sniffer will attempt using winsock instead of pcap
WINSOCK=1;

--Scroll to the bottom for the event function defs
--void Recv(packet, interface); = runs when a packet is recived
--bool Tick(); = runs every tick as defined by TICK, if this returns true the progam will die
--int,int GetTextColor(); = returns background and text-color
--void SetTextColor(background,text); = Sets the color of the text (to be printed)
--array DNS(address) = Resolves the address and returns a table containing its IP addresses or nil on failure
--string GetHostName() = Get your hostname
--void CLS() = Clears the console
--int GetKey() = awaits a keyboard input and returns its ID (ascii) when a key is hit
--bool HasKeyDown() = returns true if a key is pressed on the keyboard
--void DumpStack() = prints the lua stack to the console
--void Put(text) = puts the text (or binary) on the console as it is (no ending endline)
--string (nil on fail) ReverseDNS(IP) = returns the host name from an IP

local file = io.open("dump.txt", "w");

local _print = print;

print = function(str, extra)

	if extra ~= nil then 
		_print(str,extra);
	else
		_print(str);
	end 
	
	if file then 
	
		if extra ~= nil then 
			file:write(str.."\t"..tostring(extra).."\n");
		else 
			file:write(str.."\n");
		end 
		
		file:flush();
	end 
end 

local allowall = true;

function Filter(data)
	
	if allowall then return true; end

	if data.destination_port and data.source_port then 
	
		if IsPort(data, 7777) or IsPort(data, 7778) then 
			return true;
		else 
			return false;
		end
    elseif data.protocol then

		return data.protocol == "tcp" and Filter(data.data);
	else 
		return false;
	end 
end 

function IsAddress(IPH, address)
	
	return IPH.destination == address or IPH.source == address;
end 

function IsPort(data, port)	
	
	return data.destination_port  == port or data.source_port == port;
end

--Concept function for user input
--endkey (or nil = enter) is the key to end at
--proc if provided as a function will run with the string as its param
--returns what the proc returned or the string if it didnt run
function UserInput(endkey,proc)

	if endkey==nil then
		endkey=13; -- enter
	elseif type(endkey)~="number" then
		endkey = tostring(endkey):byte();
	end

	if endkey < 0 or endkey > 255 then
		endkey=13; -- enter
	end

	local str = "";
	local key;

	repeat

		key = GetKey();

		--esc
		if(key==27)then
			return nil;
		end

		Put(string.char(key));

		if key==8 and str:len() > 0 then
			str = str:sub(1,str:len()-1);
		else
			str = str .. string.char(key);
		end

	until key == endkey

	if type(proc)=="function" then
		return proc(str);
	end

	return str;
end

local dnscache = {};
function ReverseDnsCache(IP)

	local host = dnscache[IP]
	if host then

		if host==IP then
			return "";
		end

		return host;
	else

		host = ReverseDNS(IP);
		if not host then
			host = "";
		end

		dnscache[IP] = host;
		return host;
	end
end

function PrintIP(IPH)

	print("IPv"..tostring(IPH.version).." "..IPH.protocol:upper().." ("..tostring(IPH.length)..")");
	print(IPH.source.." ("..ReverseDnsCache(IPH.source)..") -> "..IPH.destination.." ("..ReverseDnsCache(IPH.destination)..")");

	if IPH.protocol=="icmp" then
		PrintICMP(IPH.data);
	elseif IPH.protocol=="tcp"then
		PrintTCP(IPH.data);
	elseif IPH.protocol=="udp" then
		PrintUDP(IPH.data);
	else
		--gsub to strip the bellsound from binary strings
		if type(IPH.data)=="string" then
			print("Data: "..IPH.data:gsub("\a", ""));
		else
			print("Data: "..tostring(IPH.data));
		end
	end

end

local ICMPCodes = {};

ICMPCodes[3]={};
ICMPCodes[3][0] = "0 = net unreachable";
ICMPCodes[3][1] = "1 = host unreachable";
ICMPCodes[3][2] = "2 = protocol unreachable";
ICMPCodes[3][3] = "3 = port unreachable";
ICMPCodes[3][4] = "4 = fragmentation needed and DF set";

ICMPCodes[11]={};
ICMPCodes[11][0] = "0 = time to live exceeded in transit";
ICMPCodes[11][1] = "1 = fragment reassembly time exceeded";

ICMPCodes[12]={};
ICMPCodes[12][0] = "0 = problem with option";

ICMPCodes[4]={};
ICMPCodes[4][0] = "0 = network overloaded";

ICMPCodes[5]={};
ICMPCodes[5][0] = "0 = Redirect datagrams for the Network";
ICMPCodes[5][1] = "1 = Redirect datagrams for the Host";
ICMPCodes[5][2] = "2 = Redirect datagrams for the Type of Service and Network";
ICMPCodes[5][3] = "3 = Redirect datagrams for the Type of Service and Host";

ICMPCodes[0]={};
ICMPCodes[0][0] = "0 = echo reply";

ICMPCodes[8]={};
ICMPCodes[8][0] = "0 = echo request";

ICMPCodes[13]={};
ICMPCodes[13][0] = "0 = timestamp request";

ICMPCodes[14]={};
ICMPCodes[14][0] = "0 = timestamp reply";

TotalCount = 0;

function PrintICMP(ICMP)

	if ICMP == nil then
		return;
	end

	local tbl_type = ICMPCodes[ICMP.type];

	if tbl_type == nil then
		print("Code/Type: " .. tostring(ICMP.code).." = unknown "..tostring(ICMP.type));
	else

		local msg = tbl_type[ICMP.code];
		if msg==nil then
			msg = tbl_type[0];
		end

		print("Code/Type: " .. msg);
	end

	--print("original: ");
	--PrintIP(ICMP.original);
end

function PrintTCP(TCP)

	--gsub to strip the bellsound from binary strings
	local msg = TCP.data:gsub("\a", "");
	local flags = "";

	for k,v in pairs(TCP.flags)do
		if v then
			flags = flags .. k .. " ";
		end
	end

	print("TCP:");
	print("PORT: " .. tostring(TCP.source_port).." -> "..tostring(TCP.destination_port));
	print("Ack: "..tostring(TCP.ack));
	print("Seq: "..tostring(TCP.seq));
	print("Flags: "..flags);
	print("Data: "..msg);
end

function PrintUDP(UDP)

	--gsub to strip the bellsound from binary strings
	local msg = UDP.data:gsub("\a", "");

	print("UDP:");
	print("PORT: " .. tostring(UDP.source_port).." -> "..tostring(UDP.destination_port));
	print("Data: "..msg);
end

function PrintHeader(IPH)

	if IPH.protocol=="icmp" then
		PrintICMP(IPH.data);
	elseif IPH.protocol=="tcp"then
		PrintTCP(IPH.data);
	elseif IPH.protocol=="udp" then
		PrintUDP(IPH.data);
	elseif IPH.protocol=="ipv6-icmp" then
		PrintICMPV6(IPH.data);
	elseif IPH.protocol=="ipv6-route" then
		PrintIPV6Route(IPH.data);
	elseif IPH.protocol=="hopopt" then
		PrintIPV6HopByhop(IPH.data);
	elseif IPH.protocol=="ipv6-frag" then
		PrintIPV6Frag(IPH.data);
	else

		if type(IPH.protocol)=="string" then
			print("protocol: "..IPH.protocol);
		end

		--gsub to strip the bellsound from binary strings
		if type(IPH.data)=="string" then
			print("Data: "..IPH.data:gsub("\a", ""));
		else
			print("Data: "..tostring(IPH.data));
		end
	end
end

function PrintICMPV6(icmp)

	print("IPv6-ICMP:");
	print("checksum: "..tostring(icmp.checksum));
	print("code: "..tostring(icmp.code));
	print("type: "..tostring(icmp.type));
end

function PrintIPV6Route(route)

	print("IPv6-Route:");
	print("length: "..tostring(icmp.length));
	print("options: "..tostring(icmp.options));
	print("routing type: "..tostring(icmp.routing_type));
	print("segments left: "..tostring(icmp.segments_left));
	print("protocol: "..tostring(icmp.protocol));
	PrintHeader(icmp);
end

function PrintIPV6HopByhop(hbh)

	print("HOP BY HOP:");
	print("length: "..tostring(hbh.length));
	print("options: "..tostring(hbh.options));
	print("protocol: "..tostring(hbh.protocol));
	PrintHeader(hbh);
end

function PrintIPV6Frag(frag)

	print("IPV6-Fragment:");
	print("identification: "..tostring(frag.identification));
	print("fragment offset: "..tostring(frag.fragment_offset));
	print("res: "..tostring(frag.res));
	print("m: "..tostring(frag.m));
	print("protocol: "..tostring(frag.protocol));
	PrintHeader(frag);
end

function PrintIPV6(IPH)

	print("IPv"..tostring(IPH.version).." "..IPH.protocol:upper().." ("..tostring(IPH.length)..")");
	print(IPH.source.." -> "..IPH.destination);

	PrintHeader(IPH);

end

--This function runs when a packet is recived
--Packet is a table contaning IPHEADER information
--Interface is the IP of the interface (adapter) it was recived on
--sniffer is the type of sniffer that got it (winsocket or pcap)
function Recv(packet,interface,sniffer)

	if not Filter(packet) then 
		return;
	end 

	TotalCount = TotalCount + 1;

	print("\n--------------------------------------------------------------------------------");
	print(sniffer.." INTERFACE: "..interface);

	if packet.version==6 then

		PrintIPV6(packet);
	else

		PrintIP(packet);
	end
end

--If a ticker exists it'll run every milisecond as defined by TICK
local first = true;
function Tick()

	if first then

		for k,v in pairs(IP) do

			if type(v)=="table" then

				for n=1,#v do
					print(tostring(n),tostring(v[n]));
				end

			else
				print(tostring(k),tostring(v));
			end
		end

		first=false;
		return false;
	end

	TITLE = "Sniffed: "..tostring(TotalCount);
	return false;
end

print("Lua startup script run!\n");
