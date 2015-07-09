
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

--use this variable to set which address to listen too
--IP = "localhost";

--If this is true then the program will wait for user input on failure
PAUSE=true;

--If this is set it'll modify the socket-buffer to a new size
--this is usable if you got high traffic on your socket
--might murder your CPU if too high
--Default: 8192
BUFFER=8192;

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
	print("Seq: "..tostring(TCP.ack));
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

function Recv(packet)

	if packet.protocol=="tcp" or packet.protocol=="udp" then
	--	return;
	end

	print("\n--------------------------------------------------------------------------------");
	PrintIP(packet);

end

print("Lua startup script run!\n");
