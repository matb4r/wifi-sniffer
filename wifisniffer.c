#include <pcap.h>
#include <signal.h>
#include <stdlib.h>

struct radiotap_header {
	u_int8_t	version;
	u_int8_t	pad;
	u_int16_t	len;
	u_int32_t present;
};

struct ieee802_11_header {
	u_int16_t	f_ctrl;
	u_int16_t	dur;
	u_int8_t	addr1[6];
	u_int8_t	addr2[6];
	u_int8_t	addr3[6];
	u_int16_t	seq;
	u_int8_t	addr4[6];
};

char* errbuf;
pcap_t* handle;

void cleanup() {
  pcap_close(handle);
  free(errbuf);
}

void stop(int signo) {
  exit(EXIT_SUCCESS);
}

void trap(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr) {
	struct radiotap_header* rt = (struct radiotap_header*) packetptr;
	struct ieee802_11_header* wl = (struct ieee802_11_header*) (packetptr + rt->len);

	u_int16_t ctrl_reversed = (wl->f_ctrl>>8) | (wl->f_ctrl<<8);
	u_int8_t version = wl->f_ctrl & 0x3;
	u_int8_t type = (wl->f_ctrl & 0xc) >> 2;
	u_int8_t subtype = (wl->f_ctrl & 0xf0) >> 4;
	u_int8_t flags = (wl->f_ctrl & 0xff00) >> 8;
		u_int8_t tods = flags & 0x1;
		u_int8_t fromds = (flags & 0x2) >> 1;
		u_int8_t morefr = (flags & 0x4) >> 2;
		u_int8_t retry = (flags & 0x8) >> 3;
		u_int8_t powman = (flags & 0x10) >> 4;
		u_int8_t moredata = (flags & 0x20) >> 5;
		u_int8_t wep = (flags & 0x40) >> 6;
		u_int8_t order = (flags & 0x80) >> 7;
	printf("Frame control:\t0x%04x\n", ctrl_reversed);
	printf("\tVersion:\t0x%x\n", version);
	if (type == 0)
		printf("\tType:\t\tManagement frame (0)\n");
	else if (type == 1)
		printf("\tType:\t\tControl frame (1)\n");
	else if (type == 2)
		printf("\tType:\t\tData frame (2)\n");

	if (type == 0 && subtype == 0)
		printf("\tSubtype:\tAssociation request (0)\n");
	else if (type == 0 && subtype == 1)
		printf("\tSubtype:\tAssociation response (1)\n");
	else if (type == 0 && subtype == 2)
		printf("\tSubtype:\tReassociation request (2)\n");
	else if (type == 0 && subtype == 3)
		printf("\tSubtype:\tReassociation response (3)\n");
	else if (type == 0 && subtype == 4)
		printf("\tSubtype:\tProbe request (4)\n");
	else if (type == 0 && subtype == 5)
		printf("\tSubtype:\tProbe response (5)\n");
	else if (type == 0 && subtype == 8)
		printf("\tSubtype:\tBeacon (8)\n");
	else if (type == 0 && subtype == 9)
		printf("\tSubtype:\tATIM (9)\n");
	else if (type == 0 && subtype == 10)
		printf("\tSubtype:\tDisassociation (10)\n");
	else if (type == 0 && subtype == 11)
		printf("\tSubtype:\tAuthentication (11)\n");
	else if (type == 0 && subtype == 12)
		printf("\tSubtype:\tDeauthentication (12)\n");
	else if (type == 0 && subtype == 13)
		printf("\tSubtype:\tAction (13)\n");

	if (type == 1 && subtype == 10)
		printf("\tSubtype:\tPS-Poll (10)\n");
	else if (type == 1 && subtype == 11)
		printf("\tSubtype:\tRTC (11)\n");
	else if (type == 1 && subtype == 12)
		printf("\tSubtype:\tCTS (12)\n");
	else if (type == 1 && subtype == 13)
		printf("\tSubtype:\tACK (13)\n");
	else if (type == 1 && subtype == 14)
		printf("\tSubtype:\tCF-End(14)\n");
	else if (type == 1 && subtype == 15)
		printf("\tSubtype:\tCF-End + CF-Ack (15)\n");

	if (type == 2 && subtype == 0)
		printf("\tSubtype:\tData (0)\n");
	else if (type == 2 && subtype == 1)
		printf("\tSubtype:\tData + CF-ack (1)\n");
	else if (type == 2 && subtype == 2)
		printf("\tSubtype:\tData + CF-poll (2)\n");
	else if (type == 2 && subtype == 3)
		printf("\tSubtype:\tData + CF-ack + CF-poll (3)\n");
	else if (type == 2 && subtype == 4)
		printf("\tSubtype:\tNull (4)\n");
	else if (type == 2 && subtype == 5)
		printf("\tSubtype:\tCF-ack (5)\n");
	else if (type == 2 && subtype == 6)
		printf("\tSubtype:\tCF-poll (6)\n");
	else if (type == 2 && subtype == 7)
		printf("\tSubtype:\tCF-ack + CF-poll (7)\n");
	else if (type == 2 && subtype == 8)
		printf("\tSubtype:\tQoS data (8)\n");
	else if (type == 2 && subtype == 9)
		printf("\tSubtype:\tQoS data + CF-ack (9)\n");
	else if (type == 2 && subtype == 10)
		printf("\tSubtype:\tQoS data + CF-poll (10)\n");
	else if (type == 2 && subtype == 11)
		printf("\tSubtype:\tQoS data + CF-ack + CF-poll (11)\n");
	else if (type == 2 && subtype == 12)
		printf("\tSubtype:\tQoS Null (12)\n");
	else if (type == 2 && subtype == 13)
		printf("\tSubtype:\tQoS + CF-poll (no data) (14)\n");
	else if (type == 2 && subtype == 15)
		printf("\tSubtype:\tQoS + CF-ack (no data) (15)\n");

	printf("\tFlags:\t\t0x%x\n", flags);
	printf("\t\tTo DS:\t\t%x\n", tods);
	printf("\t\tFrom DS:\t%x\n", fromds);
	printf("\t\tMore fragments:\t%x\n", morefr);
	printf("\t\tRetry:\t\t%x\n", retry);
	printf("\t\tPower manag.:\t%x\n", powman);
	printf("\t\tMore data:\t%x\n", moredata);
	printf("\t\tWEP:\t\t%x\n", wep);
	printf("\t\tOrder:\t\t%x\n", order);

	printf("Duration:\t%d\n", wl->dur);
	printf("Sequence:\t%d\n", wl->seq);

	if(tods == 0 && fromds == 0) {
		printf("Source address:\t\t%02x:%02x:%02x:%02x:%02x:%02x\n", 
					 wl->addr2[0], wl->addr2[1], wl->addr2[2],
					 wl->addr2[3], wl->addr2[4], wl->addr2[5]);
		printf("Destination address:\t%02x:%02x:%02x:%02x:%02x:%02x\n", 
					 wl->addr1[0], wl->addr1[1], wl->addr1[2],
					 wl->addr1[3], wl->addr1[4], wl->addr1[5]);
		printf("Assecc point:\t\t%02x:%02x:%02x:%02x:%02x:%02x\n", 
					 wl->addr3[0], wl->addr3[1], wl->addr3[2],
					 wl->addr3[3], wl->addr3[4], wl->addr3[5]);
	} else if (tods == 0 && fromds == 1) {
		printf("Source address:\t\t%02x:%02x:%02x:%02x:%02x:%02x\n", 
					 wl->addr3[0], wl->addr3[1], wl->addr3[2],
					 wl->addr3[3], wl->addr3[4], wl->addr3[5]);
		printf("Destination address:\t%02x:%02x:%02x:%02x:%02x:%02x\n", 
					 wl->addr1[0], wl->addr1[1], wl->addr1[2],
					 wl->addr1[3], wl->addr1[4], wl->addr1[5]);
		printf("Assecc point:\t\t%02x:%02x:%02x:%02x:%02x:%02x\n", 
					 wl->addr2[0], wl->addr2[1], wl->addr2[2],
					 wl->addr2[3], wl->addr2[4], wl->addr2[5]);
	} else if (tods == 1 && fromds == 0) {
		printf("Source address:\t\t%02x:%02x:%02x:%02x:%02x:%02x\n", 
					 wl->addr2[0], wl->addr2[1], wl->addr2[2],
					 wl->addr2[3], wl->addr2[4], wl->addr2[5]);
		printf("Destination address:\t%02x:%02x:%02x:%02x:%02x:%02x\n", 
					 wl->addr3[0], wl->addr3[1], wl->addr3[2],
					 wl->addr3[3], wl->addr3[4], wl->addr3[5]);
		printf("Assecc point:\t\t%02x:%02x:%02x:%02x:%02x:%02x\n", 
					 wl->addr1[0], wl->addr1[1], wl->addr1[2],
					 wl->addr1[3], wl->addr1[4], wl->addr1[5]);
	} else if (tods == 1 && fromds == 1) {
		printf("Source access pooint:\t\t%02x:%02x:%02x:%02x:%02x:%02x\n", 
					 wl->addr2[0], wl->addr2[1], wl->addr2[2],
					 wl->addr2[3], wl->addr2[4], wl->addr2[5]);
		printf("Destination access point:\t%02x:%02x:%02x:%02x:%02x:%02x\n", 
					 wl->addr1[0], wl->addr1[1], wl->addr1[2],
					 wl->addr1[3], wl->addr1[4], wl->addr1[5]);
		printf("Source address:\t\t%02x:%02x:%02x:%02x:%02x:%02x\n", 
					 wl->addr4[0], wl->addr4[1], wl->addr4[2],
					 wl->addr4[3], wl->addr4[4], wl->addr4[5]);
		printf("Destination address:\t%02x:%02x:%02x:%02x:%02x:%02x\n", 
					 wl->addr3[0], wl->addr3[1], wl->addr3[2],
					 wl->addr3[3], wl->addr3[4], wl->addr3[5]);
	}
	printf( "=========================================\n\n");
}

int main(int argc, char** argv) {
  atexit(cleanup);
  signal(SIGINT, stop);
  errbuf = malloc(PCAP_ERRBUF_SIZE);
  handle = pcap_create(argv[1], errbuf);
  pcap_set_rfmon(handle, 1); // monitor mode
  pcap_set_snaplen(handle, 65535);
  pcap_activate(handle);
  pcap_loop(handle, -1, trap, NULL);
}
