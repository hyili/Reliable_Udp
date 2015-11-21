/*
 * Reliable Udp transport layer protocol
 */

#define WINDOW_SIZE 4
#define PACKET_SIZE 1500
#define HEADER_SIZE 21
#define DATA_SIZE 1400

#define TYPE_SYN 48
#define TYPE_ACK 49
#define TYPE_NAK 50
#define TYPE_FIN 51
#define TYPE_RST 52
#define TYPE_FINACK 53

#define RETRANSMISSION_TIME 500000

int global_seq_num;
int global_buffer_len;
struct uwindow* global_window;
char global_buffer[DATA_SIZE + 1];

/* udp header */
struct uheader {
	/* sequence number */
	int seq_num;
	/* packet type including syn ack nak fin rst */
	char type;
	/* packet len of whole packet */
	int len;
};

/* udp packet */
struct upacket {
	/* header pointer */
	struct uheader* header;
	/* packet content (+1 for '\n') */
	char data[DATA_SIZE + 1];
};

/* udp packet window */
struct uwindow {
	/* packet array for easily fetching the specific packet */
	struct upacket* packet[WINDOW_SIZE];
	/* packet which has been ACKed
	 * for receiver, -1 : no packet, 0 : packet stored
	 * for sender, -1 : no SYN/ACK packet send/recv, 0 : packet is sent, but not ACKed, 1 : packet ACKed
	 */
	char packet_ACK[WINDOW_SIZE];
	/* head index */
	int head;
	/* tail index */
	int tail;
	/* the socket used by the window */
	int socket_fd;
	/* for my address information */
	struct sockaddr_in* my_addr;
	/* for remote host address information */
	struct sockaddr_in* remote_addr;
	/* number of packets in window */
	int number_of_packet_in_window;
	/* number of packet dropped */
	int number_of_packet_drop;
	/* file size */
	int file_size;
	/* first seq_num the seq_num at index head */
	int first_seq_num;
};

char* bstrncpy(char* , const char*, unsigned int);
void retransmission(int);
int set_alarm(int, char*, int);
int seq_num_generator();
struct upacket* new_packet(char*, int, char, int);
struct uwindow* new_window(int, struct sockaddr_in*, struct sockaddr_in*);
int rm_packet(struct upacket*);
int rm_window(struct uwindow*);
int packet_to_string(struct upacket*, char*, int);
struct upacket* string_to_packet(char*);
int three_way_handshake_s(struct uwindow*, int);
int three_way_handshake_r(struct uwindow*);
int four_way_handshake_s(struct uwindow*);
int four_way_handshake_r(struct uwindow*);
int fetch_mesg(struct uwindow*, char*, int);
int store_packet(struct uwindow*, struct upacket*);
int send_packet(struct uwindow*, struct upacket*);
int recv_packet(struct uwindow*, int);
int window_process(struct uwindow*, int, char*, int);
int rsend(char*, int, char*, int);
int rrecv(int, char*, int);
