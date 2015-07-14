
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

--IP if its a table it'll attempt listening to the interfaces (adapters)
--with their respective IP
IP = {};
IP[0] = "localhost";
IP[1] = "CAROLEAN";

--IP can also be a single address
--IP="127.0.0.1";

--IP can also be nil, then it'll listen to the first non loopback interface
--IP=nil;

--If this is true then the program will wait for user input on failure
PAUSE=true;

--Time in miliseconds between the Tick function is proc-ed (Tick())
TICK=500;

--If this is set it'll modify the socket-buffer to a new size
--this is usable if you got high traffic on your socket
--increase if your CPU is too shit to handle the amount of data you're reciving
--Default: 8192
BUFFER=8192;

--Scroll to the bottom for the event function defs
--void Recv(packet, interface); = runs when a packet is recived
--bool Tick(); = runs every tick as defined by TICK, if this returns true the progam will die

function PrintIP(IPH)

	print(IPH.protocol:upper().." ("..tostring(IPH.length)..")");
	print(IPH.source.." -> "..IPH.destination);

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

--This function runs when a packet is recived
--Packet is a table contaning IPHEADER information
--Interface is the IP of the interface (adapter) it was recived on
function Recv(packet,interface)

	--if true then return;end

	print("\n--------------------------------------------------------------------------------");
	print("INTERFACE: "..interface);
	PrintIP(packet);

end

--If a ticker exists it'll run every milisecond as defined by TICK
--function Tick()print("TICK");return false;end

print("Lua startup script run!\n");
