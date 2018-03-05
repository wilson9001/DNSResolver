#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_flags;

typedef struct
{
	char *name;
	dns_rr_type type;
	dns_rr_class class;
	dns_rr_ttl ttl;
	dns_rdata_len rdata_len;
	unsigned char *rdata;
} dns_rr;

struct dns_answer_entry;
struct dns_answer_entry
{
	char *value;
	struct dns_answer_entry *next;
};
typedef struct dns_answer_entry dns_answer_entry;

const int MAXLENGTH = 2000;

void print_bytes(unsigned char *bytes, int byteslen)
{
	int i, j, byteslen_adjusted;
	unsigned char c;

	if (byteslen % 8)
	{
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	}
	else
	{
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++)
	{
		if (!(i % 8))
		{
			if (i > 0)
			{
				for (j = i - 8; j < i; j++)
				{
					if (j >= byteslen_adjusted)
					{
						printf("  ");
					}
					else if (j >= byteslen)
					{
						printf("  ");
					}
					else if (bytes[j] >= '!' && bytes[j] <= '~')
					{
						printf(" %c", bytes[j]);
					}
					else
					{
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted)
			{
				printf("\n%02X: ", i);
			}
		}
		else if (!(i % 4))
		{
			printf(" ");
		}
		if (i >= byteslen_adjusted)
		{
			continue;
		}
		else if (i >= byteslen)
		{
			printf("   ");
		}
		else
		{
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}

void canonicalize_name(char *name)
{
	/*
	 * Canonicalize name in place.  Change all upper-case characters to
	 * lower case and remove the trailing dot if there is any.  If the name
	 * passed is a single dot, "." (representing the root zone), then it
	 * should stay the same.
	 *
	 * INPUT:  name: the domain name that should be canonicalized in place
	 */

	int namelen, i;

	// leave the root zone alone
	if (strcmp(name, ".") == 0)
	{
		return;
	}

	namelen = strlen(name);
	// remove the trailing dot, if any
	if (name[namelen - 1] == '.')
	{
		name[namelen - 1] = '\0';
	}

	// make all upper-case letters lower case
	for (i = 0; i < namelen; i++)
	{
		if (name[i] >= 'A' && name[i] <= 'Z')
		{
			name[i] += 32;
		}
	}
}

/* 
	 * Convert a DNS name from string representation (dot-separated labels)
	 * to DNS wire format, using the provided byte array (wire).  Return
	 * the number of bytes used by the name in wire format.
	 *
	 * INPUT:  name: the string containing the domain name
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *              wire-formatted name should be constructed
	 * OUTPUT: the length of the wire-formatted name.
	 */
int name_ascii_to_wire(char *name, unsigned char *wire)
{
	const char separator[2] = ".";
	int offset = 0;

	char *token;

	//get first token
	token = strtok(name, separator);

	//add to wire and then get rest of tokens
	while (token)
	{
		//add length of next section to wire
		unsigned char tokenLength = (unsigned char)strlen(token);
		*wire = tokenLength;
		wire++;
		offset++;

		//add each character to wire
		for (unsigned char i = 0; i < tokenLength; i++)
		{
			*wire = (unsigned char)token[i];
			wire++;
			offset++;
		}

		token = strtok(NULL, separator);
	}

	return offset;
}

char *name_ascii_from_wire(unsigned char *wire, int *indexp)
{
	/* 
	 * Extract the wire-formatted DNS name at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return its string
	 * representation (dot-separated labels) in a char array allocated for
	 * that purpose.  Update the value pointed to by indexp to the next
	 * value beyond the name.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp, a pointer to the index in the wire where the
	 *              wire-formatted name begins
	 * OUTPUT: a string containing the string representation of the name,
	 *              allocated on the heap.
	 */
}

dns_rr rr_from_wire(unsigned char *wire, int *indexp, int query_only)
{
	/* 
	 * Extract the wire-formatted resource record at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return a 
	 * dns_rr (struct) populated with its contents. Update the value
	 * pointed to by indexp to the next value beyond the resource record.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp: a pointer to the index in the wire where the
	 *              wire-formatted resource record begins
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are extracting a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the resource record (struct)
	 */
}

/* 
	 * Convert a DNS resource record struct to DNS wire format, using the
	 * provided byte array (wire).  Return the number of bytes used by the
	 * name in wire format.
	 *
	 * INPUT:  rr: the dns_rr struct containing the rr record
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *             wire-formatted resource record should be constructed
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are constructing a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the length of the wire-formatted resource record.
	 *
	 */
int rr_to_wire(dns_rr rr, unsigned char *wire, int query_only)
{

	if (query_only)
	{
		dns_rr_class class = rr.class;
		dns_rr_type type = rr.type;

		unsigned char class1 = *((unsigned char *)&class);
		unsigned char class2 = *((unsigned char *)&class + 1);
		unsigned char type1 = *((unsigned char *)&type);
		unsigned char type2 = *((unsigned char *)&type + 1);

		*wire = type1;
		wire++;
		*wire = type2;
		wire++;
		*wire = class1;
		wire++;
		*wire = class2;

		return 4;
	}
	else
	{
		fprintf(stderr, "rr_to_wire was somehow called for a non-query RR.\n");
		return 0;
	}
}

/* 
	* Create a wire-formatted DNS (query) message using the provided byte
	* array (wire).  Create the header and question sections, including
	* the qname and qtype.
	*
	* INPUT:  qname: the string containing the name to be queried
	* INPUT:  qtype: the integer representation of type of the query (type A == 1)
	* INPUT:  wire: the pointer to the array of bytes where the DNS wire message should be constructed
	* OUTPUT: the length of the DNS wire message
*/
unsigned short create_dns_query(char *qname, dns_rr_type qtype, unsigned char *wire)
{
	//Create header values
	dns_rr_class RRClass = htons(0x0001);
	dns_flags flags = htons(0x0100);
	unsigned short offset = 0;

	//Create random ID for query
	srand(time(NULL));
	dns_query_id queryID = (unsigned short)rand();

	unsigned char ID1 = *((unsigned char *)&queryID);
	unsigned char ID2 = *((unsigned char *)&queryID + 1);
	unsigned char flags1 = *((unsigned char *)&flags);
	unsigned char flags2 = *((unsigned char *)&flags + 1);

	//begin wire with query ID
	*wire = ID1;
	wire++;
	offset++;
	*wire = ID2;
	wire++;
	offset++;
	//add flags
	*wire = flags1;
	wire++;
	offset++;
	*wire = flags2;
	wire++;
	offset++;
	//Total questions = 1
	*wire = 0;
	wire++;
	offset++;
	*wire = 0x01;
	wire++;
	offset++;
	//No RR's
	for (int i = 0; i < 6; i++)
	{
		*wire = 0;
		wire++;
		offset++;
	}

	//Convert query name to unsigned char[]
	int nameBytes = name_ascii_to_wire(qname, wire);

	if (!nameBytes)
	{
		fprintf(stderr, "Failed to convert query name to DNS format!\n");
		exit(EXIT_FAILURE);
	}

	offset += (unsigned short)nameBytes;
	wire += nameBytes;

	*wire = 0;
	wire++;
	offset++;

	dns_rr resourceRecord;
	resourceRecord.class = RRClass;
	resourceRecord.type = qtype;

	int rrBytes = rr_to_wire(resourceRecord, wire, true);
	if (!rrBytes)
	{
		fprintf(stderr, "Failed to convert resource record to DNS format!\n");
		exit(EXIT_FAILURE);
	}

	offset += (unsigned short)rrBytes;
	wire += rrBytes;
	//wire -= offset;

	return offset;
}

dns_answer_entry *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *wire)
{
	/* 
	 * Extract the IPv4 address from the answer section, following any
	 * aliases that might be found, and return the string representation of
	 * the IP address.  If no address is found, then return NULL.
	 *
	 * INPUT:  qname: the string containing the name that was queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes representing the DNS wire message
	 * OUTPUT: a linked list of dns_answer_entrys the value member of each
	 * reflecting either the name or IP address.  If
	 */
}

int send_recv_message(unsigned char *request, int requestlen, unsigned char *response, char *server, unsigned short port)
{
	/* 
	 * Send a message (request) over UDP to a server (server) and port
	 * (port) and wait for a response, which is placed in another byte
	 * array (response).  Create a socket, "connect()" it to the
	 * appropriate destination, and then use send() and recv();
	 *
	 * INPUT:  request: a pointer to an array of bytes that should be sent
	 * INPUT:  requestlen: the length of request, in bytes.
	 * INPUT:  response: a pointer to an array of bytes in which the
	 *             response should be received
	 * OUTPUT: the size (bytes) of the response received
	 */
}

dns_answer_entry *resolve(char *qname, char *server)
{
	unsigned char queryWireInitial[MAXLENGTH];
	//unsigned char *queryWireStart = queryWireInitial;

	//Create DNS-friendly query
	unsigned short wireLength = create_dns_query(qname, htons(0x0001), queryWireInitial);

	unsigned char queryWireFinal[wireLength];

	for (int i = 0; i < wireLength; i++)
	{
		//queryWireFinal[i] = queryWireStart[i];
		queryWireFinal[i] = queryWireInitial[i];
	}

	printf("Outgoing wire:\n");
	for (int i = 1; i <= wireLength; i++)
	{
		printf("%x ", queryWireFinal[i - 1]);
		if (i % 4 == 0)
		{
			printf("\n");
		}
	}

	printf("\n\n");

	exit(EXIT_SUCCESS);
	//Send query
}

int main(int argc, char *argv[])
{
	dns_answer_entry *ans;
	if (argc < 3)
	{
		fprintf(stderr, "Usage: %s <domain name> <server>\n", argv[0]);
		exit(1);
	}
	ans = resolve(argv[1], argv[2]);
	while (ans != NULL)
	{
		printf("%s\n", ans->value);
		ans = ans->next;
	}
}

/*
The first task is organizing the various components of the DNS query into a DNS query message. The query
message is simply an array of unsigned char, which can be transmitted to the server over a UDP socket.
Building the contents of that array is a matter of organizing and formatting the query components according
to the DNS protocol specification. There are two major parts to the DNS query message: the DNS header
and the DNS question section, which contains the query.

The create dns query() function has been declared in resolver.c and is intended as a helper func-
tion to build the unsigned char array which will be transmitted to the server. Other helper functions in-
clude name ascii to wire() and rr to wire(), also declared in resolver.c but left as an exer-
cise to you to define. Note also the typedef declarations for dns rr and struct dns answer entry
and the various DNS fields (e.g., dns rr type).
The following functions might be useful for your message composition: strok(), strlen(), strncpy(),
memcpy(), and (in some cases) malloc.
*/

/*
DNS Header Format:
|00|01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|
|						Identification			|QR|   Opcode  |AA|TC|RD|RA|Z |AD|CD|   Rcode   |
|						Total Questions			|				Total Answer RRs				|
|					Total Authority RRs			|		       Total Additonal RRs				|

Identification. 16 bits.
Used to match request/reply packets.

QR, Query/Response. 1 bit.
0 = Query
1 = Response

Opcode. 4 bits. Since we are always doing standard query, this will be 0.

AA, Authoritative Answer. 1 bit.
Specifies that the responding name server is an authority for the domain name in question section. Note that the contents of the answer section may have multiple owner names because of aliases. This bit corresponds to the name which matches the query name, or the first owner name in the answer section.

TC, Truncated. 1 bit.
Indicates that only the first 512 bytes of the reply was returned.

RD, Recursion Desired. 1 bit.
May be set in a query and is copied into the response. If set, the name server is directed to pursue the query recursively. Recursive query support is optional.

RA, Recursion Available. 1 bit.
Indicates if recursive query support is available in the name server.

Z. 1 bit.

AD, Authenticated data. 1 bit.
Indicates in a response that all data included in the answer and authority sections of the response have been authenticated by the server according to the policies of that server. It should be set only if all data in the response has been cryptographically verified or otherwise meets the server's local security policy.

CD, Checking Disabled. 1 bit.

Rcode, Return code. 4 bits.

0 = Success
1 = Format error
2 = Server failure
3 = Name error (meaningful only for authoritative servers)
4 = Not implemented
5 = Refused
6 = Name should not exist but does
7 = RR set should not exist but does
8 = RR set should exist but does not
9 = Server not authoritative
10 = Name not in zone

Total Questions. 16 bits, unsigned.
Number of entries in the question list that were returned.
Ours will be 1

Total Answer RRs. 16 bits, unsigned.
Number of entries in the answer resource record list that were returned.
Ours will be 0

Total Authority RRs. 16 bits, unsigned.
Number of entries in the authority resource record list that were returned.
Ours will be 0

Total Additional RRs. 16 bits, unsigned.
Number of entries in the additional resource record list that were returned.
Ours will be 0

Questions[]. Variable length.
A list of zero or more Query structures.
Ours will have 1

Answer RRs[]. Variable length.
A list of zero or more Answer Resource Record structures.
Ours will have 0

Authority RRs[]. Variable length.
A list of zero or more Authority Resource Record structures.
Ours will have 0
Additional RRs[]. Variable length.
A list of zero or more Additional Resource Record structures.
Ours will have 0

Query. Variable length.
|00	01	02	03	04	05	06	07 	08	09	10	11	12	13	14	15 	16	17	18	19	20	21	22	23 	24	25	26	27	28	29	30	31|
|													   Query Name :::														  |
|							 Type 							   |							 Class							  |

Resource Record. Variable length.
|00	01	02	03	04	05	06	07 	08	09	10	11	12	13	14	15 	16	17	18	19	20	21	22	23 	24	25	26	27	28	29	30	31|
|														   Name :::															  |
|							 Type 							   |							 Class							  |
|															  TTL															  |
|						  Rdata Length 						   |							Rdata :::						  |

Type. 16 bits, unsigned.
1 = A (PIv4 address)
28 = AAAA (IPv6 address)

Class. 16 bits, unsigned.
Ours will always be 1 for internet

Authoritative Server.
(RFC 2182) A server that knows the content of a DNS zone from local knowledge, and thus can answer queries about that zone without needing to query other servers.

For example, a query for www.example.com looks like this:
27 d6 01 00
00 01 00 00
00 00 00 00
03 77 77 77
07 65 78 61
6d 70 6c 65
03 63 6f 6d
00 00 01 00
01

This is equivalent to:
unsigned char msg[] = {
0x27, 0xd6, 0x01, 0x00,
0x00, 0x01, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x03, 0x77, 0x77, 0x77,
0x07, 0x65, 0x78, 0x61,
0x6d, 0x70, 0x6c, 0x65,
0x03, 0x63, 0x6f, 0x6d,
0x00, 0x00, 0x01, 0x00,
0x01
};


DNS Header Format:
|00|01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|
|0  0  1  0  0  1  1  1  1  1  0  1  0  1  1  0 |0  0  0  0  0  0  0  1  0  0  0  0  0  0  0  0 | <--0x27, 0xd6, 0x01, 0x00
|						Identification			|QR|   Opcode  |AA|TC|RD|RA|Z |AD|CD|   Rcode   |
|0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  1 |0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0 | <--0x00, 0x01, 0x00, 0x00
|						Total Questions			|				Total Answer RRs				|
|0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0 |0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0 | <--0x00, 0x00, 0x00, 0x00
|					Total Authority RRs			|		       Total Additonal RRs				|


• Identification (query ID): 0x27d6 This value is arbitrary and is typically randomly-generated when
the query is formed (note that network protocols use network byte order, which is equivalent to Big-
endian (most significant bytes are on the left).
• QR flag: 0 (query)
• Opcode: 0 (standard query)
• Flags: The RD bit is set (1); all others are cleared (0).
• Total questions: 1 (again, note the network byte ordering)
• Total answer RRs: 0
• Total authority RRs: 0
• Total additional RRs: 0
And the question section contains the query:
• Query name: www.example.com, encoded as follows (encoding method shown later):
03 77 77 77
07 65 78 61
6d 70 6c 65
03 63 6f 6d
00

• Type: 1 (type A for address)
• Class: 1 (IN for Internet class)

Note that in this lab, you will only be issuing queryies for type 1 (A) and class 1 (IN). The header will
largely look the same for all queries produced by your resolver—with only the Query ID changing (to
random values). Similarly, the Question section will look the same, withonly the query name changing.

Encoding is as follows:

03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
   w  w  w     e  x  a  m  p  l  e     c  o  m

The length of each label precedes the characters comprising the label itself (e.g., the value 3 precedes the
three bytes representing the ASCII values www). A 0 in the length byte always indicates the end of the
labels. Dots don't need to be encoded because they are implied by the next length indicator.

The last two bytes give the type and class of the query.
0x00 0x01 means type A (IPv4 Query)
0x00 0x01 is class IN for internet
*/