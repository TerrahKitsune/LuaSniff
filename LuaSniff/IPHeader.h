#include <Windows.h>

//Max size a datagram/packet can be
#define PACKET_SIZE_MAX 65535

#define HI_PART(x)  ((x>>4) & 0x0F)
#define LO_PART(x)  ((x) & 0x0F)

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

typedef struct _HOP_BY_HOP_
{
	BYTE	next_header;
	BYTE	hdr_ext_len;
	BYTE	options[14];
} HOP_BY_HOP;

typedef struct _IPV6_ROUTING_
{
	BYTE	next_header;
	BYTE	hdr_ext_len;
	BYTE	routing_type;
	BYTE	segments_left;
	BYTE	data[12];

} IPV6_ROUTING;

typedef struct _IPV6_FRAGMENT_
{
	BYTE	next_header;
	BYTE	reserved;
	WORD	fragmentoffset_res_m;
	DWORD	identification;

} IPV6_FRAGMENT;

typedef struct _IP_HEADER_
{
	BYTE  ver_ihl;        // Version (4 bits) and Internet Header Length (4 bits)
	BYTE  type;           // Type of Service (8 bits)
	WORD  length;         // Total size of packet (header + data)(16 bits)
	WORD  packet_id;      // (16 bits)
	WORD  flags_foff;     // Flags (3 bits) and Fragment Offset (13 bits)
	BYTE  time_to_live;   // (8 bits)
	BYTE  protocol;       // (8 bits)
	WORD  hdr_chksum;     // Header check sum (16 bits)
	DWORD source_ip;      // Source Address (32 bits)
	DWORD destination_ip; // Destination Address (32 bits)
	DWORD options_padding;// Options and padding (32 bits)
} IPHEADER;

typedef struct _IPV6_HEADER_
{
	DWORD ver_tc_fl;			// Version (4 bits), Traffic cass (8 bits), Flow label (20 bits)
	WORD  length;				// Total size of packet (header + data)(16 bits)
	BYTE  next_header;			// (8 bits)
	BYTE  hop_limit;			// (8bits)
	BYTE source_ip[16];			// Source Address (128 bits)
	BYTE destination_ip[16];	// Destination Address (128 bits)
} IPV6HEADER;

typedef struct _ICMP_HEADER_
{
	BYTE type;               // (8 bits)  
	BYTE code;               // (8 bits)  
	WORD checksum;           // (16 bits) 
	IPHEADER original;		 // Original datagram
} ICMPHEADER;

typedef struct _IPV6_ICMP_HEADER_
{
	BYTE type;               // (8 bits)  
	BYTE code;               // (8 bits)  
	WORD checksum;           // (16 bits) 
	DWORD message;			 // (32)
} IPV6ICMPHEADER;

typedef struct _TCP_HEADER_
{
	WORD  source_port;       // (16 bits)
	WORD  destination_port;  // (16 bits)
	DWORD seq_number;        // Sequence Number (32 bits)
	DWORD ack_number;        // Acknowledgment Number (32 bits)
	WORD  info_ctrl;         // Data Offset (4 bits), Reserved (6 bits), Control bits (6 bits)
	WORD  window;            // (16 bits)
	WORD  checksum;          // (16 bits)
	WORD  urgent_pointer;    // (16 bits)
	DWORD options_padding;	 // (24 bits options, 8bit padding)
} TCPHEADER;

typedef struct _UDP_HEADER_
{
	WORD  source_port;       // (16 bits)
	WORD  destination_port;  // (16 bits)
	WORD  conver_checksum;	 // (16 bits)
	WORD  checksum;			 // (16 bits)

}UDPHEADER;