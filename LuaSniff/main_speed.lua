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
WINSOCK=false;

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

--Concept function for user input
--endkey (or nil = enter) is the key to end at
--proc if provided as a function will run with the string as its param
--returns what the proc returned or the string if it didnt run

cls = CLS;

local Data = {};
local CollectedDown = {};
CollectedDown.byte=0;
CollectedDown.kilo=0;
CollectedDown.mega=0;
CollectedDown.giga=0;
CollectedDown.tera=0;
CollectedDown.all=0;

local CollectedUp = {};
CollectedUp.byte=0;
CollectedUp.kilo=0;
CollectedUp.mega=0;
CollectedUp.giga=0;
CollectedUp.tera=0;
CollectedUp.all=0;

function AddToCollected(bytes,Collected)

	Collected.all = Collected.all + bytes;

	Collected.byte = Collected.byte + bytes;

	while Collected.byte > 1000 do
		Collected.kilo = Collected.kilo + 1;
		Collected.byte = Collected.byte - 1000;
	end

	while Collected.kilo > 1000 do
		Collected.mega = Collected.mega + 1;
		Collected.kilo = Collected.kilo - 1000;
	end

	while Collected.mega > 1000 do
		Collected.giga = Collected.giga + 1;
		Collected.mega = Collected.mega - 1000;
	end

	while Collected.giga > 1000 do
		Collected.tera = Collected.tera + 1;
		Collected.giga = Collected.giga - 1000;
	end
end

function Recv(packet,interface)

	local p = Data[interface];

	packet.Time = os.clock();
	table.insert(p,packet);
end

function ColorPrint(text,backgroud,foreground,pleft,pright)

	local b,f = GetTextColor();
	SetTextColor(backgroud,foreground);

	if pleft and pleft > 0 then

		for n=1,pleft do
			io.write(" ");
		end
	end

	io.write(text);

	if pright and pright > 0 then

		pright = pright - text:len();

		if pright > 0 then

			for n=1,pright do
				io.write(" ");
			end
		end
	end
	SetTextColor(b,f);
end

local function GetSpeedString(data)

	--10 seconds
	data = data / 10;

	local speed = data/1000;
	local notation = "B/sec";

	if speed > 1.0 then

		notation = "KB/sec";
		data = speed;

		speed = data/1000;
		if speed > 1.0 then

			notation = "MB/sec";
			data = speed;

			speed = data/1000;
			if speed > 1.0 then
				notation = "GB/sec";
				data = speed;
			end
		end
	end
	return tostring(data),notation;
end

local updatecnt = 2;
local cnt=updatecnt;

local function Ticker()

	if cnt >= updatecnt then
		cnt=0;
	else
		cnt = cnt + 1;
		return;
	end

	local t = os.clock();
	local cdata = {};
	local up,down;
	local udpup,udpdown;
	local tcpup,tcpdown;
	local othertcpup,othertcpdown;
	local speed,note;
	local tup,tdown = 0,0;

	for k,v in pairs(Data)do

		up=0;
		down=0;
		udpup=0;
		udpdown=0;
		tcpup=0;
		tcpdown=0;
		othertcpup=0;
		othertcpdown=0;

		for kk,vv in pairs(v)do

			if t-vv.Time > 10.0 then
				v[kk]=nil;
			else
				if vv.destination==k then

					down = down + vv.length;
					AddToCollected(vv.length,CollectedDown);

					if vv.protocol=="tcp" then
						tcpdown = tcpdown + vv.length;
					elseif vv.protocol=="udp" then
						udpdown = udpdown + vv.length;
					else
						othertcpdown = othertcpdown + vv.length;
					end
				else

					up = up + vv.length;
					AddToCollected(vv.length,CollectedUp);

					if vv.protocol=="tcp" then
						tcpup = tcpup + vv.length;
					elseif vv.protocol=="udp" then
						udpup = udpup + vv.length;
					else
						othertcpup = othertcpup + vv.length;
					end
				end
			end
		end

		tup = tup + up;
		tdown = tdown + down;

		if up > 0 or down > 0 then

			cdata[k]={};

			cdata[k].Up = up;
			cdata[k].Down = down;

			cdata[k].TcpUp = tcpup;
			cdata[k].TcpDown = tcpdown;

			cdata[k].UdpUp = udpup;
			cdata[k].UdpDown = udpdown;

			cdata[k].OtherUp = othertcpup;
			cdata[k].OtherDown = othertcpdown;
		end
	end

	cls();
	for k,v in pairs(cdata)do

		--if k:len()<15 then
		--	ColorPrint(k,1,0xD,0,15);
		--else
			ColorPrint(k,1,0xD,0,80);
			--io.write("\n");
			ColorPrint("->",1,0xD,0,15);
		--end

		speed,note = GetSpeedString(v.Down);

		ColorPrint("DOWN",1,7,2,5);
		ColorPrint(tostring(speed),1,0x2,2,10);
		ColorPrint(note,1,0x2,1,8);

		ColorPrint("|",1,7,0,0);

		speed,note = GetSpeedString(v.Up);

		ColorPrint("UP",1,7,2,5);
		ColorPrint(tostring(speed),1,0xc,2,10);
		ColorPrint(note,1,0xc,1,16);

		ColorPrint("-TCP:",0,0xb,0,15);

		speed,note = GetSpeedString(v.TcpDown);

		ColorPrint("DOWN",0,7,2,5);
		ColorPrint(tostring(speed),0,0x2,2,10);
		ColorPrint(note,0,0x2,1,8);

		io.write("|");

		speed,note = GetSpeedString(v.TcpUp);

		ColorPrint("UP",0,7,2,5);
		ColorPrint(tostring(speed),0,0xc,2,10);
		ColorPrint(note,0,0xc,1,5);

		io.write("\n");

		ColorPrint("-UDP:",0,0xe,0,15);

		speed,note = GetSpeedString(v.UdpDown);

		ColorPrint("DOWN",0,7,2,5);
		ColorPrint(tostring(speed),0,0x2,2,10);
		ColorPrint(note,0,0x2,1,8);

		io.write("|");

		speed,note = GetSpeedString(v.UdpUp);

		ColorPrint("UP",0,7,2,5);
		ColorPrint(tostring(speed),0,0xc,2,10);
		ColorPrint(note,0,0xc,1,5);

		io.write("\n");

		ColorPrint("-OTHER:",0,0xf,0,15);

		speed,note = GetSpeedString(v.OtherDown);

		ColorPrint("DOWN",0,7,2,5);
		ColorPrint(tostring(speed),0,0x2,2,10);
		ColorPrint(note,0,0x2,1,8);

		io.write("|");

		speed,note = GetSpeedString(v.OtherUp);

		ColorPrint("UP",0,7,2,5);
		ColorPrint(tostring(speed),0,0xc,2,10);
		ColorPrint(note,0,0xc,1,5);
		io.write("\n\n");

	end

	speed,note = GetSpeedString(tdown);

	TITLE = "TOTAL DOWN/UP: "..tostring(speed).." "..note.." | ";

	speed,note = GetSpeedString(tup);

	TITLE = TITLE .. tostring(speed).." "..note;

	io.write("\n\n");

	--ColorPrint(text,backgroud,foreground,pleft,pright)

	local offset = 40;

	ColorPrint("DOWNLOADED BYTES: " .. tostring(CollectedDown.all),0,0x2,0,offset);
	ColorPrint("UPLOADED BYTES: " .. tostring(CollectedUp.all).."\n\n",0,0xc,0,0);

	ColorPrint("TB: "..tostring(CollectedDown.tera),0,0x2,0,offset);
	ColorPrint("TB: "..tostring(CollectedUp.tera).."\n",0,0xc,0,0);

	ColorPrint("GB: "..tostring(CollectedDown.giga),0,0x2,0,offset);
	ColorPrint("GB: "..tostring(CollectedUp.giga).."\n",0,0xc,0,0);

	ColorPrint("MB: "..tostring(CollectedDown.mega),0,0x2,0,offset);
	ColorPrint("MB: "..tostring(CollectedUp.mega).."\n",0,0xc,0,0);

	ColorPrint("KB: "..tostring(CollectedDown.kilo),0,0x2,0,offset);
	ColorPrint("KB: "..tostring(CollectedUp.kilo).."\n",0,0xc,0,0);

	ColorPrint(" B: "..tostring(CollectedDown.byte),0,0x2,0,offset);
	ColorPrint(" B: "..tostring(CollectedUp.byte).."\n",0,0xc,0,0);

	return false;
end

function Tick()

	print(tostring(IP));

	if type(IP)=="string" then
		Data[IP]={};
		print(IP);
	else
		for k,v in pairs(IP)do

			if type(v)=="string" then

				Data[v]={};
				print(k,v);
			else
				for kk,vv in pairs(v)do
					Data[vv]={};
					print(kk,vv);
				end
			end
		end
	end

	Tick = Ticker;
end



print("Lua startup script run!\n");
