#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <unistd.h>

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_flags;

/*union
{
	unsigned char ch[2];
	unsigned short sh;
} charToShort;*/

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
	//unsigned char c;

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

/*
	 * Canonicalize name in place.  Change all upper-case characters to
	 * lower case and remove the trailing dot if there is any.  If the name
	 * passed is a single dot, "." (representing the root zone), then it
	 * should stay the same.
	 *
	 * INPUT:  name: the domain name that should be canonicalized in place
	 */
void canonicalize_name(char *name)
{
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

//Helper function to convert the next two unsigned chars in network order (by placement) to an unsigned short in host order.
unsigned short charsToShort(unsigned char *wire, int byteOffset)
{
	unsigned char toJoin[] = {wire[byteOffset++], wire[byteOffset]};

	//printf("Chars to short are: %d %d, ", toJoin[0], toJoin[1]);

	unsigned short beforeEndianConversion;

	memcpy(&beforeEndianConversion, toJoin, 2);

	//printf("Short value is: %d\n", ntohs(beforeEndianConversion));

	return ntohs(beforeEndianConversion);
}

/* 
	 * Extract the wire-formatted DNS name at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return its string
	 * representation (dot-separated labels) in a char array allocated for
	 * that purpose.  Update the value pointed to by indexp to the next
	 * value beyond the name.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp, a pointer to the index in the wire where the wire-formatted name begins
	 * OUTPUT: a string containing the string representation of the name, allocated on the heap.
	 */
char *name_ascii_from_wire(unsigned char *wire, int *indexp)
{
	char *name = (char *)malloc(/*sizeof(char) * */ 200);
	int nameIndex = 0;

	while (wire[*indexp])
	{
		//This section of name is compresed and must be extracted from elsewhere in the wire.
		if (wire[*indexp] >= 192)
		{
			(*indexp)++;
			unsigned char beginningIndex = wire[*indexp];
			//(*indexp)++;

			//printf("\tCompression detected. Beginning index is %d\n", beginningIndex);

			while (wire[beginningIndex])
			{
				if (wire[beginningIndex] >= 192) ///Need to add recursive decompression
				{
					beginningIndex++;
					//printf("\t\tRecursive compression detected. Recursive index is %d\n", wire[beginningIndex]);
					int offset = (int)wire[beginningIndex];
					char *compressedSection = name_ascii_from_wire(wire, &offset);
					int sectionLength = strlen(compressedSection);
					//printf("\t\tRecursively compressed section was %s with length %d\n", compressedSection, sectionLength);
					//strcpy((char *)&name[nameIndex], compressedSection);
					for(int i = 0; i < sectionLength; i++)
					{
						name[nameIndex++] = compressedSection[i];
					}
					
					break;
				}

				else
				{
					char sectionLength = wire[beginningIndex++];
					//printf("Section length is %d\n", sectionLength);

					for (int i = 0; i < sectionLength; i++)
					{
						name[nameIndex++] = wire[beginningIndex++];
					}
					name[nameIndex++] = '.';
				}
			}
			//Once you go to compression then you are done with the name.
//printf("\tName is now %ld bytes long, equals %s\n", strlen(name), name);
			break;
		}
		else //This section of the name is not compressed.
		{
			char sectionLength = wire[(*indexp)++]; /////

			for (int i = 0; i < sectionLength; i++) /////
			{
				name[nameIndex++] = wire[(*indexp)++];
			}
			name[nameIndex++] = '.';
		}
	}
	(*indexp)++;

	return name;
}

/* 
	 * Extract the wire-formatted resource record at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return a 
	 * dns_rr (struct) populated with its contents. Update the value
	 * pointed to by indexp to the next value beyond the resource record.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp: a pointer to the index in the wire where the wire-formatted resource record begins
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether we are extracting a full resource record or only a query (i.e., in the question section
	 *  of the DNS message).  In the case of the latter, the ttl, rdata_len, and rdata are skipped.
	 * OUTPUT: the resource record (struct)
	 */
dns_rr rr_from_wire(unsigned char *wire, int *indexp, int query_only)
{
	dns_rr resourceRecord;

	resourceRecord.name = name_ascii_from_wire(wire, indexp);
	//printf("Final RR name is %s\n", resourceRecord.name);
	//printf("About to convert record type. Index is %d\n", *indexp); //value begins at index 145 with 1D |64| 6E

	resourceRecord.type = charsToShort(wire, *indexp);
	*indexp += 2;
	//printf("Record type is: %d\n", resourceRecord.type);

	resourceRecord.class = charsToShort(wire, *indexp);
	*indexp += 2;

	unsigned char TTLBytes[4];

	TTLBytes[0] = wire[(*indexp)++];
	TTLBytes[1] = wire[(*indexp)++];
	TTLBytes[2] = wire[(*indexp)++];
	TTLBytes[3] = wire[(*indexp)++];

	int ttl;

	memcpy(&ttl, TTLBytes, 4);

	resourceRecord.ttl = ntohl(ttl);

	resourceRecord.rdata_len = charsToShort(wire, *indexp);
	*indexp += 2;

	//printf("rdata_length is %d\n", resourceRecord.rdata_len);
	unsigned char *rData = (unsigned char *)malloc(resourceRecord.rdata_len);
	//unsigned char rData[resourceRecord.rdata_len];
	//printf("Resource Record created successfully\n");

if(resourceRecord.type == 1)
{
	for (int i = 0; i < resourceRecord.rdata_len; i++)
	{
		rData[i] = wire[(*indexp)++];
	}
}
else if(resourceRecord.type == 5)/////
{
	rData = (unsigned char *) name_ascii_from_wire(wire, indexp);
}
	resourceRecord.rdata = rData;

	return resourceRecord;
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
		//dns_rr_type type = rr.type;

		unsigned char class1 = *((unsigned char *)&class);
		unsigned char class2 = *((unsigned char *)&class + 1);
		unsigned char type1 = 0; //*((unsigned char *)&type);
		unsigned char type2 = 1; //*((unsigned char *)&type + 1);

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
		//fprintf(stderr, "Failed to convert query name to DNS format!\n");
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

	return offset;
}

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
dns_answer_entry *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *wire)
{
	/*
	set qname to the initial name queried
	(i.e., the query name in the question section)
	for each resource record (RR) in the answer section:
	if the owner name of RR matches qname and the type matches the qtype:
	extract the address from the RR, convert it to a string, and add it
	to the result list
	else if the owner name of RR matches qname and the type is (5) CNAME:
	the name is an alias; extract the canonical name from the RR rdata,
	and set qname to that value, and add it to the result list
	return NULL (no match was found)
	*/

	//remove header and check for proper response
	int byteOffset = 0;
	//skip identification
	byteOffset += 2;

	/*unsigned char QRandRD = wire[byteOffset];
	byteOffset++;
	unsigned char otherFlags = wire[byteOffset];
	byteoffSet++;
	unsigned char 
	if(QRandRD != 0x81 || otherFlags != 0x80)
	{

	}*/

	//Test beginning of header
	if (wire[byteOffset++] != 0x81 || wire[byteOffset++] != 0x80 || wire[byteOffset++] != 0 || wire[byteOffset++] != 0x01)
	{
		//fprintf(stderr, "Beginning of response header is incorrect!\n");
	}

	//Get RR count
	unsigned short RRCount = charsToShort(wire, byteOffset);
	byteOffset += 2;
	unsigned short authorityRRCount = charsToShort(wire, byteOffset);
	byteOffset += 2;
	unsigned short additionalRRCount = charsToShort(wire, byteOffset);
	byteOffset += 2;

	unsigned short totalRRCount = RRCount + authorityRRCount + additionalRRCount;
	//If no RR's found then we return NULL
	if (!totalRRCount)
	{
		return NULL;
	}
	//printf("RRCount is: %d\n", totalRRCount);
	//we can skip the question header we don't need it
	while (wire[byteOffset] != 0x00)
	{
		unsigned char sectionLength = wire[byteOffset++];
		byteOffset += sectionLength;
	}

	byteOffset += 5;

	//Now we begin extracting RR's
	dns_rr RRarray[totalRRCount];
	int arrayIndex = 0;

	dns_answer_entry *answerEntries = NULL;
	dns_answer_entry *nextEntry = NULL;

	/*
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
	*/

	//Gather all RR's
	for (; arrayIndex < totalRRCount; arrayIndex++)
	{
		RRarray[arrayIndex] = rr_from_wire(wire, &byteOffset, false);
		//printf("Name here is %s\n", RRarray[arrayIndex].name);
	}

	//Initialize RR list
	if (arrayIndex)
	{
		//printf("Resource record returned. Values are: %s,%d\n", (char *)RRarray[0].rdata, RRarray[0].type);

		if (RRarray[0].type == qtype || RRarray[0].type == 5)
		{
			//printf("First record is type %d\n", RRarray[0].type);
			nextEntry = (dns_answer_entry *)malloc(sizeof(dns_answer_entry));
			//printf("Created first record struct\n");

			answerEntries = nextEntry;

			if (RRarray[0].type == qtype)
			{
				//strcpy(nextEntry->value, RRarray[0].rdata);
				nextEntry->value = (char *)malloc(INET_ADDRSTRLEN);
				//printf("Teapot\n");
				inet_ntop(AF_INET, RRarray[0].rdata, nextEntry->value, INET_ADDRSTRLEN);
			}
			else if (RRarray[0].type == 5) //Name is an alias
			{
				//printf("Before name canonicalized: %s\n", RRarray[0].rdata);
				//canonicalize_name((char *)RRarray[0].name);
				//printf("After name canonicalized: %s\n", RRarray[0].rdata);
				nextEntry->value = (char *)RRarray[0].rdata;
				//strcpy(nextEntry->value, RRarray[0].rdata);
			}
		}
	}

	//Create rest of list
	for (int i = 1; i < arrayIndex; i++)
	{
		//printf("RRarray name is %s", RRarray[i].name);
		//if (!strcmp(RRarray[i].name, qname))
		//{
		//printf("Array type is %d\n", RRarray[i].type);
		if (RRarray[i].type == qtype || RRarray[i].type == 5)
		{
			nextEntry->next = (dns_answer_entry *)malloc(sizeof(dns_answer_entry));
			nextEntry = nextEntry->next;

			nextEntry->next = NULL;

			if (RRarray[i].type == qtype)
			{
				//printf("ABout to strcpy. Data is %s\n", (char *)RRarray[i].rdata);
				nextEntry->value = (char *)malloc(INET_ADDRSTRLEN);
				//strcpy(nextEntry->value, (char *) RRarray[i].rdata);
				inet_ntop(AF_INET, RRarray[i].rdata, nextEntry->value, INET_ADDRSTRLEN);
				//printf("successfully copied\n");
			}
			else if (RRarray[i].type == 5) //Name is an alias
			{
				//printf("Before name canonicalized: %s\n", RRarray[i].rdata);
				//canonicalize_name((char *)RRarray[i].name);
				printf("After name canonicalized: %s\n", RRarray[i].rdata);
				nextEntry->value = (char *)RRarray[i].rdata;
			}
		}
		//}
	}
	return answerEntries;
}

/* 
	 * Send a message (request) over UDP to a server (server) and port
	 * (port) and wait for a response, which is placed in another byte
	 * array (response).  Create a socket, "connect()" it to the
	 * appropriate destination, and then use send() and recv();
	 *
	 * INPUT:  request: a pointer to an array of bytes that should be sent
	 * INPUT:  requestlen: the length of request, in bytes.
	 * INPUT:  response: a pointer to an array of bytes in which the response should be received
	 * OUTPUT: the size (bytes) of the response received
	 */
int send_recv_message(unsigned char *request, int requestlen, unsigned char *response, char *server, unsigned short port)
{
	struct sockaddr_in ip4addr;

	ip4addr.sin_family = AF_INET;
	ip4addr.sin_port = htons(port);

	inet_pton(AF_INET, server, &ip4addr.sin_addr);

	int sfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (connect(sfd, (struct sockaddr *)&ip4addr, sizeof(struct sockaddr_in)) < 0)
	{
		fprintf(stderr, "Could not connect!\n");
		exit(EXIT_FAILURE);
	}

	if (write(sfd, request, requestlen) != requestlen)
	{
		fprintf(stderr, "Partial or failed transmission to DNS server!\n");
		exit(EXIT_FAILURE);
	}

	int nread = read(sfd, /*(void *)*/ response, MAXLENGTH);

	if (nread == -1)
	{
		perror("read");
		exit(EXIT_FAILURE);
	}

	return nread;
}

dns_answer_entry *resolve(char *qname, char *server)
{
	unsigned char queryWireInitial[MAXLENGTH];
	dns_rr_type qtype = 1;
	//Create DNS-friendly query
	unsigned short wireLength = create_dns_query(qname, qtype, queryWireInitial);

	unsigned char queryWireFinal[wireLength];

	for (int i = 0; i < wireLength; i++)
	{
		queryWireFinal[i] = queryWireInitial[i];
	}

	/*printf("Outgoing wire:\n");
	for (int i = 1; i <= wireLength; i++)
	{
		printf("%x ", queryWireFinal[i - 1]);
		if (i % 4 == 0)
		{
			printf("\n");
		}
	}

	printf("\n\n");*/

	//Send query
	unsigned char responseWire[MAXLENGTH];
	//port 53 is for DNS, 80 is usual HTTP
	/*int responseBytes =*/ send_recv_message(queryWireFinal, wireLength, responseWire, server, 53);

	//printf("Recieved %d bytes from DNS server.\n", responseBytes);

	//print_bytes(responseWire, responseBytes);

	//parse message and return list of RR's
	return get_answer_address(qname, qtype, responseWire);
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