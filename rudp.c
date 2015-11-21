/*
 * Reliable Udp transport layer protocol
 * Packet Format:
 * -------------------------------------------------
 * | seq_num 10bytes | type 1 bytes | len 10 bytes |
 * -------------------------------------------------
 * |         data DATA_SIZE - HEADER_SIZE          |
 * -------------------------------------------------
 * When retransmission, SYN's sequence won't change, but the ACK's sequence will.
 *
 */

#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "rudp.h"

/* revise the problem cause by the strncpy function */
char* bstrncpy(char* s1, const char* s2, unsigned int n) {
	char *s = s1;
	while (n > 0) {
		*s++ = *s2++;
		--n;
	}

	return s1;
}

/* using SIGALRM to retransmit the data which does not get the ACK */
void retransmission(int sig_no) {
	/* for handshake transmission */
	socklen_t socket_len = sizeof(*global_window->remote_addr);

	fprintf(stderr, "timeout retransmit\n");
	if (global_buffer_len != -1) {
		if (sendto(global_window->socket_fd, global_buffer, global_buffer_len, 0, (struct sockaddr*)global_window->remote_addr, socket_len) < 0) {
			fprintf(stderr, "%s %d\n", global_buffer, global_buffer_len);
			fprintf(stderr, "%d %s\n", errno, strerror(errno));
			fprintf(stderr, "write to server failed\n");
		}
	}
	/* for data transmission */
	else {
		
	}
}

/* set alarm */
int set_alarm(int time, char* buffer, int buffer_len) {
	/* set the time(us) */
	ualarm(time, time);

	/* this is for handshake transmission */
	if ((buffer != NULL) && (buffer_len != -1)) {
		memset(global_buffer, 0, DATA_SIZE);
		bstrncpy(global_buffer, buffer, buffer_len<DATA_SIZE?buffer_len:DATA_SIZE);
		global_buffer_len = buffer_len;
	}
	/* this is for data transmission */
	else {
		// just using global window
	}

	return 0;
}

/* create a sequence number */
int seq_num_generator() {
	if (global_seq_num == 0) {
		global_seq_num = (int)abs(rand())%10000;
		return global_seq_num;
	}
	else {
		global_seq_num++;
		return global_seq_num;
	}
}

/* create a new rudp packet with an identified sequence number */
struct upacket* new_packet(char* data, int len, char type, int seq_num) {
	struct upacket* packet = (struct upacket*)malloc(sizeof(struct upacket));
	struct uheader* header = (struct uheader*)malloc(sizeof(struct uheader));
	int i;

	packet->header = header;
	memset(packet->data, 0, DATA_SIZE);
	if (data != NULL) {
		if (len <= DATA_SIZE) {
			bstrncpy(packet->data, data, len);
		}
		else {
			free(packet);
			free(header);

			return NULL;
		}
	}

	if (seq_num == 0) {
		header->seq_num = seq_num_generator();
	}
	else {
		header->seq_num = seq_num;
	}
	header->type = type;
	/* DATA_SIZE(array size) + 10(seq_num) + 1(type) + 10(len) */
	header->len = len + HEADER_SIZE;

	return packet;
}

/* create a new rudp packet window */
struct uwindow* new_window(int socket_fd, struct sockaddr_in* my_addr, struct sockaddr_in* remote_addr) {
	struct uwindow* window = (struct uwindow*)malloc(sizeof(struct uwindow));
	int i;

	for (i = 0; i < WINDOW_SIZE; i++) {
		window->packet[i] = NULL;
		window->packet_ACK[i] = -1;
	}
	window->head = 0;
	window->tail = 0;
	window->socket_fd = socket_fd;
	window->my_addr = my_addr;
	window->remote_addr = remote_addr;
	window->number_of_packet_in_window = 0;
	window->number_of_packet_drop = 0;
	window->file_size = 0;
	window->first_seq_num = 0;

	/* set the rand seed with time function */
	global_seq_num = 0;
	srand((int)time(NULL));

	return window;
}

/* destroy the specified packet, return 0 when success(means there is nothing in it) */
int rm_packet(struct upacket* packet) {
	if (packet != NULL) {
		free(packet->header);
		free(packet);
	}

	return 0;
}

/* destroy the specified window, return 0 when success(means there is nothing in it) */
int rm_window(struct uwindow* window) {
	int i;

	for (i = 0; i < WINDOW_SIZE; i++) {
		if (rm_packet(window->packet[i])) {
			fprintf(stderr, "remove packet failed\n");
			return -1;
		}
		window->packet[i] = NULL;
	}

	/* reset the rand seed */
	global_seq_num = 0;
	free(window);
	return 0;
}

/* transform the whole packet to string */
int packet_to_string(struct upacket* packet, char* data, int len) {
	//snprintf(data, len, "%10d%c%10d%s", packet->header->seq_num, packet->header->type, packet->header->len, packet->data);
	snprintf(data, len, "%10d%c%10d", packet->header->seq_num, packet->header->type, packet->header->len);
	bstrncpy(data+HEADER_SIZE, packet->data, len);
	return len;
}

/* transform the string received to packet */
struct upacket* string_to_packet(char* data) {
	struct upacket* packet;
	char seq_num[10];
	char type[1];
	char len[10];

	bstrncpy(seq_num, data, 10);
	bstrncpy(type, data+10, 1);
	bstrncpy(len, data+11, 10);
	packet = new_packet(data+HEADER_SIZE, atoi(len)-HEADER_SIZE, *type, atoi(seq_num));

	return packet;
}

/* the three way handshake function for sender */
int three_way_handshake_s(struct uwindow* window, int len) {
	/* sendto(socket_fd, mesg, len, 0, (struct sockaddr*)&serv_addr, socket_len)
	 * recvfrom(socket_fd, mesg, len, 0, (struct sockaddr*)&client_addr, &socket_len)
	 */
	
	int socket_fd = window->socket_fd;
	struct sockaddr_in* my_addr = window->my_addr;
	struct sockaddr_in* remote_addr = window->remote_addr;
	socklen_t socket_len = sizeof(*remote_addr);
	struct upacket *packet_s, *packet_r;

	char* mesg = (char*)malloc(11*sizeof(char));
	char* buffer = (char*)malloc(100*sizeof(char));
	int buffer_len = 0;
	
	/* set retransmission function */
	signal(SIGALRM, retransmission);

	/* clear the buffer */
	memset(buffer, 0, 100);
	memset(mesg, 0, 10);

	/* initialize file_size */
	window->file_size = len;

	/* create the first SYN packet : contains the first seq_num and the size of whole file */
	snprintf(mesg, 11, "%10d", window->file_size);
	packet_s = new_packet(mesg, 10, TYPE_SYN, 0);
	buffer_len = packet_to_string(packet_s, buffer, 100);

	/* DEBUG message */
	fprintf(stderr, "DEBUG three way handshake_s\n");
	/* DEBUG message */

	if (sendto(socket_fd, buffer, buffer_len, 0, (struct sockaddr*)remote_addr, socket_len) < 0) {
		fprintf(stderr, "%s %d\n", buffer, buffer_len);
		fprintf(stderr, "%d %s\n", errno, strerror(errno));
		fprintf(stderr, "write to server failed\n");
		return -1;
	}
	set_alarm(RETRANSMISSION_TIME, buffer, buffer_len);

	/* clear the buffer */
	memset(buffer, 0, 100);

	/* wait for the SYNACK packet */
	/* DEBUG message */
	fprintf(stderr, "DEBUG three way handshake_s\n");
	/* DEBUG message */

	if (recvfrom(socket_fd, buffer, 100, 0, (struct sockaddr*)remote_addr, &socket_len) < 0) {
		fprintf(stderr, "%s\n", buffer);
		fprintf(stderr, "%d %s\n", errno, strerror(errno));
		fprintf(stderr, "read from server failed\n");
		return -1;
	}
	set_alarm(0, buffer, buffer_len);

	packet_r = string_to_packet(buffer);

	/* check if the SYNACK is right */
	if (packet_s->header->seq_num != atoi(packet_r->data)) {
		fprintf(stderr, "sync failed\n");
		return -1;
	}

	/* initialize the first_seq_num */
	window->first_seq_num = packet_s->header->seq_num + 1;

	/* clear the packet and free the buffer */
	rm_packet(packet_s);
	rm_packet(packet_r);
	free(mesg);
	free(buffer);

	/* DEBUG message */
	fprintf(stderr, "DEBUG three way handshake_s\n");
	/* DEBUG message */

	return 0;
}

/* the three way handshake function for receiver, return the file size sent from sender */
int three_way_handshake_r(struct uwindow* window) {
	/* sendto(socket_fd, mesg, len, 0, (struct sockaddr*)&serv_addr, socket_len)
	 * recvfrom(socket_fd, mesg, len, 0, (struct sockaddr*)&client_addr, &socket_len)
	 */

	int socket_fd = window->socket_fd;
	struct sockaddr_in* my_addr = window->my_addr;
	struct sockaddr_in* remote_addr = window->remote_addr;
	socklen_t socket_len = sizeof(*remote_addr);
	struct upacket *packet_s, *packet_r;

	char* mesg = (char*)malloc(11*sizeof(char));
	char* buffer = (char*)malloc(100*sizeof(char));
	int buffer_len = 0;
	int len = 0;

	/* set retransmission function */
	signal(SIGALRM, retransmission);

	/* clear the buffer */
	memset(buffer, 0, 100);
	memset(mesg, 0, 10);

	/* wait for the SYN packet */
	/* DEBUG message */
	fprintf(stderr, "DEBUG three way handshake_r\n");
	/* DEBUG message */

	if (recvfrom(socket_fd, buffer, 100, 0, (struct sockaddr*)remote_addr, &socket_len) < 0) {
		fprintf(stderr, "%s\n", buffer);
		fprintf(stderr, "%d %s\n", errno, strerror(errno));
		fprintf(stderr, "read from client failed\n");
		return -1;
	}

	packet_r = string_to_packet(buffer);

	/* extract the file size message, and initialize file_size */
	len = atoi(packet_r->data);
	window->file_size = len;
	
	/* send the SYNACK packet back */
	snprintf(mesg, 11, "%10d", packet_r->header->seq_num);
	packet_s = new_packet(mesg, 10, TYPE_ACK, 0);
	buffer_len = packet_to_string(packet_s, buffer, 100);

	/* DEBUG message */
	fprintf(stderr, "DEBUG three way handshake_r\n");
	/* DEBUG message */

	if (sendto(socket_fd, buffer, buffer_len, 0, (struct sockaddr*)remote_addr, socket_len) < 0) {
		fprintf(stderr, "%s %d\n", buffer, buffer_len);
		fprintf(stderr, "%d %s\n", errno, strerror(errno));
		fprintf(stderr, "write to client failed\n");
		return -1;
	}
	set_alarm(RETRANSMISSION_TIME, buffer, buffer_len);

	/* initialize the first_seq_num */
	window->first_seq_num = packet_s->header->seq_num + 1;

	/* clear the packet and free the buffer */
	rm_packet(packet_s);
	rm_packet(packet_r);
	free(mesg);
	free(buffer);

	/* DEBUG message */
	fprintf(stderr, "DEBUG three way handshake_r\n");
	/* DEBUG message */

	return len;
}

/* the four way handshake function for sender */
int four_way_handshake_s(struct uwindow* window) {
	/* sendto(socket_fd, mesg, len, 0, (struct sockaddr*)&serv_addr, socket_len)
	 * recvfrom(socket_fd, mesg, len, 0, (struct sockaddr*)&client_addr, &socket_len)
	 */

	int socket_fd = window->socket_fd;
	struct sockaddr_in* my_addr = window->my_addr;
	struct sockaddr_in* remote_addr = window->remote_addr;
	socklen_t socket_len = sizeof(*remote_addr);
	struct upacket *packet_s, *packet_r;

	char* mesg = (char*)malloc(11*sizeof(char));
	char* buffer = (char*)malloc(100*sizeof(char));
	int buffer_len = 0;
	
	/* set retransmission function */
	signal(SIGALRM, retransmission);

	/* clear the buffer */
	memset(buffer, 0, 100);
	memset(mesg, 0, 10);

	/* create the first FIN packet */
	packet_s = new_packet(mesg, 0, TYPE_FIN, 0);
	buffer_len = packet_to_string(packet_s, buffer, 100);

	/* DEBUG message */
	fprintf(stderr, "DEBUG four way handshake_s\n");
	/* DEBUG message */

	if (sendto(socket_fd, buffer, buffer_len, 0, (struct sockaddr*)remote_addr, socket_len) < 0) {
		fprintf(stderr, "%s %d\n", buffer, buffer_len);
		fprintf(stderr, "%d %s\n", errno, strerror(errno));
		fprintf(stderr, "write to server failed\n");
		return -1;
	}
	set_alarm(RETRANSMISSION_TIME, buffer, buffer_len);

	/* clear the buffer */
	memset(buffer, 0, 100);

	/* DEBUG message */
	fprintf(stderr, "DEBUG four way handshake_s\n");
	/* DEBUG message */

	while (1) {
		/* wait for the ACK packet */
		if (recvfrom(socket_fd, buffer, 100, 0, (struct sockaddr*)remote_addr, &socket_len) < 0) {
			fprintf(stderr, "%s\n", buffer);
			fprintf(stderr, "%d %s\n", errno, strerror(errno));
			fprintf(stderr, "read from server failed\n");
			return -1;
		}

		packet_r = string_to_packet(buffer);

		/* check if the ACK is right */
		if ((packet_r->header->type == TYPE_FINACK) || (packet_r->header->type == TYPE_FIN)) {
			if ((packet_s->header->seq_num != atoi(packet_r->data)) && (packet_s->header->seq_num + 1 != atoi(packet_r->data))) {
				fprintf(stderr, "sync failed\n");
				return -1;
			}
			else {
				break;
			}
		}
		/* clear the packet and the buffer */
		else {
			rm_packet(packet_r);
			memset(buffer, 0, 100);
		}
	}
	set_alarm(0, buffer, buffer_len);

	/* clear the packet and the buffer */
	rm_packet(packet_s);
	memset(buffer, 0, 100);

	/* send the ACK packet back */
	snprintf(mesg, 11, "%10d", packet_r->header->seq_num);
	packet_s = new_packet(mesg, 10, TYPE_FINACK, 0);
	buffer_len = packet_to_string(packet_s, buffer, 100);

	/* DEBUG message */
	fprintf(stderr, "DEBUG four way handshake_s\n");
	/* DEBUG message */

	if (sendto(socket_fd, buffer, buffer_len, 0, (struct sockaddr*)remote_addr, socket_len) < 0) {
		fprintf(stderr, "%s %d\n", buffer, buffer_len);
		fprintf(stderr, "%d %s\n", errno, strerror(errno));
		fprintf(stderr, "write to server error\n");
		return -1;
	}

	/* close the socket */
	close(socket_fd);

	/* clear the packet and free the buffer */
	rm_packet(packet_s);
	rm_packet(packet_r);
	free(buffer);
	free(mesg);

	/* DEBUG message */
	fprintf(stderr, "DEBUG four way handshake_s\n");
	/* DEBUG message */

	return 0;
}

/* the four way handshake function for receiver */
int four_way_handshake_r(struct uwindow* window) {
	/* sendto(socket_fd, mesg, len, 0, (struct sockaddr*)&serv_addr, socket_len)
	 * recvfrom(socket_fd, mesg, len, 0, (struct sockaddr*)&client_addr, &socket_len)
	 */

	int socket_fd = window->socket_fd;
	struct sockaddr_in* my_addr = window->my_addr;
	struct sockaddr_in* remote_addr = window->remote_addr;
	socklen_t socket_len = sizeof(*remote_addr);
	struct upacket *packet_s, *packet_r;

	char* mesg = (char*)malloc(11*sizeof(char));
	char* buffer = (char*)malloc(100*sizeof(char));
	int buffer_len = 0;
	int len = 0;

	/* set retransmission function */
	signal(SIGALRM, retransmission);

	/* DEBUG message */
	fprintf(stderr, "DEBUG four way handshake_r\n");
	/* DEBUG message */

	/* clear the buffer */
	memset(buffer, 0, 100);
	memset(mesg, 0, 10);

	/* wait for FIN packet */
	while (1) {
		if (recvfrom(socket_fd, buffer, 100, 0, (struct sockaddr*)remote_addr, &socket_len) < 0) {
			fprintf(stderr, "%s\n", buffer);
			fprintf(stderr, "%d %s\n", errno, strerror(errno));
			fprintf(stderr, "read from client failed\n");
			return -1;
		}

		packet_r = string_to_packet(buffer);

		/* check if the FIN is right */
		if (packet_r->header->type == TYPE_FIN) {
			break;
		}
		/* clear the packet and the buffer */
		else {
			rm_packet(packet_r);
			free(buffer);
		}
	}

	/* clear the buffer */
	memset(buffer, 0, 100);

	/* send the ACK packet back */
	snprintf(mesg, 11, "%10d", packet_r->header->seq_num);
	packet_s = new_packet(mesg, 10, TYPE_FINACK, 0);
	buffer_len = packet_to_string(packet_s, buffer, 100);

	/* DEBUG message */
	fprintf(stderr, "DEBUG four way handshake_r\n");
	/* DEBUG message */

	if (sendto(socket_fd, buffer, buffer_len, 0, (struct sockaddr*)remote_addr, socket_len) < 0) {
		fprintf(stderr, "%s %d\n", buffer, buffer_len);
		fprintf(stderr, "%d %s\n", errno, strerror(errno));
		fprintf(stderr, "write to client failed\n");
		return -1;
	}
	set_alarm(RETRANSMISSION_TIME, buffer, buffer_len);

	/* clear the packet and the buffer */
	rm_packet(packet_s);
	memset(buffer, 0, 100);

	/* send the FIN packet */
	packet_s = new_packet(mesg, 10, TYPE_FIN, 0);
	buffer_len = packet_to_string(packet_s, buffer, 100);

	/* DEBUG message */
	fprintf(stderr, "DEBUG four way handshake_r\n");
	/* DEBUG message */

	if (sendto(socket_fd, buffer, buffer_len, 0, (struct sockaddr*)remote_addr, socket_len) < 0) {
		fprintf(stderr, "%s %d\n", buffer, buffer_len);
		fprintf(stderr, "%d %s\n", errno, strerror(errno));
		fprintf(stderr, "write to client failed\n");
		return -1;
	}
	set_alarm(RETRANSMISSION_TIME, buffer, buffer_len);

	/* clear the buffer */
	memset(buffer, 0, 100);
	memset(mesg, 0, 10);

	/* DEBUG message */
	fprintf(stderr, "DEBUG four way handshake_r\n");
	/* DEBUG message */

	/* wait for the ACK packet */
	while (1) {
		if (recvfrom(socket_fd, buffer, 100, 0, (struct sockaddr*)remote_addr, &socket_len) < 0) {
			fprintf(stderr, "%s\n", buffer);
			fprintf(stderr, "%d %s\n", errno, strerror(errno));
			fprintf(stderr, "read from client failed\n");
			return -1;
		}

		packet_r = string_to_packet(buffer);

		/* check if the ACK is right */
		if (packet_r->header->type == TYPE_FINACK) {
			if ((packet_s->header->seq_num != atoi(packet_r->data)) && (packet_s->header->seq_num - 1 != atoi(packet_r->data))) {
				fprintf(stderr, "sync failed\n");
				return -1;
			}
			else {
				break;
			}
		}
		/* clear the packet and the buffer */
		else {
			rm_packet(packet_r);
			memset(buffer, 0, 100);
		}
	}
	set_alarm(0, buffer, buffer_len);

	/* close the socket */

	/* clear the packet and free the buffer */
	rm_packet(packet_s);
	rm_packet(packet_r);
	free(buffer);

	/* DEBUG message */
	fprintf(stderr, "DEBUG four way handshake_r\n");
	/* DEBUG message */

	return 0;
}

/* fetch the message from received packet in the window, return the length of fetch message, return -1 if message is longer in given space */
int fetch_mesg(struct uwindow* window, char* mesg, int len) {
	/* just watching */
	//fprintf(stderr, "%s\n", window->packet[window->head]->data);

	/* PROCESSING */
	struct upacket* packet;
	char* packet_ACK;
	int total_len;
	int temp_len;

	total_len = 0;
	while (window->number_of_packet_in_window > 0 && len > 0) {
		packet = window->packet[window->head];
		packet_ACK = &(window->packet_ACK[window->head]);
		if (*packet_ACK == 0) {
			/* DEBUG message */
			fprintf(stderr, "DEBUG fetch_message1 total_len = %d, len = %d\n", total_len, len);
			/* DEBUG message */

			bstrncpy(mesg, packet->data, temp_len = len>packet->header->len-HEADER_SIZE?packet->header->len-HEADER_SIZE:len);
			len -= temp_len;
			total_len += temp_len;
			mesg += temp_len;

			/* ... can delete it now ... */
			window->packet_ACK[window->head] = -1;
			rm_packet(packet);
			window->packet[window->head] = NULL;
			if (++(window->head) >= WINDOW_SIZE) {
				window->head = 0;
			}
			window->number_of_packet_in_window--;
			window->number_of_packet_drop++;
			window->first_seq_num++;
		}
		else {
			/* DEBUG message */
			fprintf(stderr, "DEBUG fetch_message2\n");
			/* DEBUG message */

			return total_len;
		}
	}
	/* DEBUG message */
	fprintf(stderr, "DEBUG fetch_message3 total_len = %d, len = %d\n", total_len, len);
	/* DEBUG message */

	return total_len;
}

/* store function, return 0 if success */
int store_packet(struct uwindow* window, struct upacket* packet) {
	/* DEBUG message */
	//fprintf(stderr, "DEBUG %d %d\n", window->head, window->tail);
	/* DEBUG message */

	if (window->packet[window->tail] == NULL) {
		window->packet[window->tail] = packet;
		window->packet_ACK[window->tail] = 0;
		window->number_of_packet_in_window++;
		if (++(window->tail) >= WINDOW_SIZE) {
			window->tail = 0;
		}
		return 0;
	}
	else {
		return -1;
	}
}

/* store the packet to the window and send it to receiver, return 0 if success */
int send_packet(struct uwindow* window, struct upacket* packet) {
	int socket_fd = window->socket_fd;
	struct sockaddr_in* my_addr = window->my_addr;
	struct sockaddr_in* remote_addr = window->remote_addr;
	socklen_t socket_len = sizeof(*remote_addr);

	char* mesg = (char*)malloc(11*sizeof(char));
	char* buffer = (char*)malloc((DATA_SIZE)*sizeof(char));
	int buffer_len = 0;

	memset(buffer, 0, DATA_SIZE);
	memset(mesg, 0, 10);

	/* DEBUG message */
	fprintf(stderr, "DEBUG send_packet\n");
	/* DEBUG message */

	buffer_len = packet_to_string(packet, buffer, packet->header->len);

	/* DEBUG message */
	fprintf(stderr, "DEBUG send_packet %d\n", packet->header->len);
	//fprintf(stderr, "%s\n", packet->data);
	//fprintf(stderr, "%d\n", buffer_len);
	/* DEBUG message */

	if (sendto(socket_fd, buffer, buffer_len, 0, (struct sockaddr*)remote_addr, socket_len) < 0) {
		fprintf(stderr, "%s %d\n", buffer, buffer_len);
		fprintf(stderr, "%d %s\n", errno, strerror(errno));
		fprintf(stderr, "write to client failed\n");
		return -1;
	}

	/* DEBUG message */
	fprintf(stderr, "DEBUG send_packet\n");
	/* DEBUG message */

	free(mesg);
	free(buffer);
	return store_packet(window, packet);
}

/* receive the packet, and store the packet to window, return 0 if success */
int recv_packet(struct uwindow* window, int type) {
	int socket_fd = window->socket_fd;
	struct sockaddr_in* my_addr = window->my_addr;
	struct sockaddr_in* remote_addr = window->remote_addr;
	socklen_t socket_len = sizeof(*remote_addr);
	int offset = 0, index = 0, i;
	
	char* mesg = (char*)malloc(11*sizeof(char));
	char* buffer = (char*)malloc((PACKET_SIZE)*sizeof(char));
	int buffer_len = 0;
	struct upacket *packet_s, *packet_r;

	memset(buffer, 0, PACKET_SIZE);
	memset(mesg, 0, 10);

	/* DEBUG message */
	fprintf(stderr, "DEBUG recv_packet\n");
	/* DEBUG message */

	if (recvfrom(socket_fd, buffer, PACKET_SIZE, 0, (struct sockaddr*)remote_addr, &socket_len) < 0) {
		fprintf(stderr, "%s\n", buffer);
		fprintf(stderr, "%d %s\n", errno, strerror(errno));
		fprintf(stderr, "read from client failed\n");
		return -1;
	}
	set_alarm(0, buffer, buffer_len);

	packet_r = string_to_packet(buffer);

	memset(buffer, 0, PACKET_SIZE);

	/* DEBUG message */
	fprintf(stderr, "DEBUG recv_packet\n");
	//fprintf(stderr, "%s\n", packet_r->data);
	/* DEBUG message */

	/* received packet handler */
	if ((packet_r->header->type == TYPE_SYN) && (type == 0)) {
		/* store the packet */
		store_packet(window, packet_r);

		/* ACK the received packet */
		/*snprintf(mesg, 11, "%10d", packet_r->header->seq_num);
		packet_s = new_packet(mesg, 10, TYPE_ACK, 0);
		buffer_len = packet_to_string(packet_s, buffer, PACKET_SIZE);*/
		int ACK_index;
		for (i = window->head, ACK_index = i; i != window->tail; i=++i<WINDOW_SIZE?i:0) {
			if (i ==  window->tail-1<0?WINDOW_SIZE-1:window->tail-1 || window->packet_ACK[i] == -1) {
				snprintf(mesg, 11, "%10d", window->packet[ACK_index]->header->seq_num);
				packet_s = new_packet(mesg, 10, TYPE_ACK, 0);
				buffer_len = packet_to_string(packet_s, buffer, PACKET_SIZE);
			}
			else {
				ACK_index = i;
			}
		}

		/* DEBUG message */
		fprintf(stderr, "DEBUG recv_packet\n");
		/* DEBUG message */

		if (sendto(socket_fd, buffer, buffer_len, 0, (struct sockaddr*)remote_addr, socket_len) < 0) {
			fprintf(stderr, "%s %d\n", buffer, buffer_len);
			fprintf(stderr, "%d %s\n", errno, strerror(errno));
			fprintf(stderr, "write to client failed\n");
			return -1;
		}

		/* DEBUG message */
		fprintf(stderr, "DEBUG recv_packet\n");
		/* DEBUG message */

		rm_packet(packet_s);
		free(mesg);
		free(buffer);

		return 0;
	}
	else if ((packet_r->header->type == TYPE_ACK) && (type == 1)) {
		/* match the packet in the window */
		/* DEBUG message */
		fprintf(stderr, "DEBUG recv_packet\n");
		/* DEBUG message */

		offset = atoi(packet_r->data) - window->first_seq_num;
		if ((offset >= WINDOW_SIZE) || (offset < 0)) {
			fprintf(stderr, "not a valid ACK packet1 recv_data = %d, offset = %d\n", atoi(packet_r->data), offset);
			return -1;
		}
		
		if (window->head + offset > WINDOW_SIZE) {
			index = window->head + offset - WINDOW_SIZE;
		}
		else {
			index = window->head + offset;
		}

		if (window->packet[index] == NULL) {
			fprintf(stderr, "not a valid ACK packet2 recv_data = %d, first_seq = %d, offset = %d\n", atoi(packet_r->data), window->first_seq_num);
			fprintf(stderr, "not a valid ACK packet2 head = %d, index = %d, offset = %d\n", window->head, index, offset);
		}

		if (window->packet_ACK[index] == 0) {
			if (window->packet[index]->header->seq_num == atoi(packet_r->data)) {
				/* DEBUG message */
				fprintf(stderr, "DEBUG recv_packet\n");
				/* DEBUG message */

				for (i = window->head; i <= index; i++) {
					/* ... can delete it now ... */
					window->packet_ACK[i] = -1;
					rm_packet(window->packet[i]);
					window->packet[i] = NULL;
					if (++(window->head) >= WINDOW_SIZE) {
						window->head = 0;
					}
					window->number_of_packet_in_window--;
					window->number_of_packet_drop++;
					window->first_seq_num++;
				}
			}
			else {
				fprintf(stderr, "some error occured\n");
				return -1;
			}
		}
		else if (window->packet_ACK[index] == -1) {
			fprintf(stderr, "not a valid ACK packet3\n");
			return -1;
		}

		/* DEBUG message */
		fprintf(stderr, "DEBUG recv_packet\n");
		/* DEBUG message */

		rm_packet(packet_r);
		free(mesg);
		free(buffer);
		return 0;
	}

	return -1;
}

/* handle the send, and recv operation(using type variable) in the specified window, and retransmit operation also */
int window_process(struct uwindow* window, int type, char* mesg, int len) {
	char* reserved_mesg = mesg;
	int reserved_len = len, result = 0;
	struct upacket* packet;

	//signal(SIGALRM, retransmission);
	//alarm(0);
	//ualarm(50, 0);

	/* for rsend handler */
	if (type == 1) {
		/* DEBUG message */
		fprintf(stderr, "DEBUG window process %d\n", reserved_len);
		//reserved_len = 0;
		/* DEBUG message */

		/* establish the connection */
		three_way_handshake_s(window, len);

		/* start to pack the packet, and send it out */
		/* what if the window is full??? while loop what to do next??? */
		while (reserved_len > 0) {
			while ((reserved_len > 0) && (window->number_of_packet_in_window < WINDOW_SIZE)) {
				if (reserved_len >= DATA_SIZE) {
					if ((packet = new_packet(reserved_mesg, DATA_SIZE, TYPE_SYN, 0)) == NULL) {
						fprintf(stderr, "create packet failed\n");
						return -1;
					}

					if (send_packet(window, packet) < 0) {
						fprintf(stderr, "send packet failed\n");
						break;
					}

					if (recv_packet(window, 1) < 0) {
						fprintf(stderr, "receive packet failed\n");
						break;
					}

					reserved_mesg += DATA_SIZE;
					reserved_len -= DATA_SIZE;
				}
				else {	
					if ((packet = new_packet(reserved_mesg, reserved_len, TYPE_SYN, 0)) == NULL) {
						fprintf(stderr, "create packet failed\n");
						return -1;
					}

					if (send_packet(window, packet) < 0) {
						fprintf(stderr, "send packet failed\n");
						break;
					}

					if (recv_packet(window, 1) < 0) {
						fprintf(stderr, "receive packet failed\n");
						break;
					}

					reserved_mesg += reserved_len;
					reserved_len = 0;
				}
			}
		}

		/* DEBUG message */
		fprintf(stderr, "DEBUG window process\n");
		/* DEBUG message */

		/* finish the connection */
		four_way_handshake_s(window);

		return 0;
	}
	/* for rrecv handler */
	else if (type == 0) {
		/* DEBUG message */
		fprintf(stderr, "DEBUG window process %d\n", reserved_len);
		//reserved_len = 0;
		/* DEBUG message */

		/* establish the connection */
		three_way_handshake_r(window);

		/* set the reserved buffer length to file_size, if file_size is bigger than buffer size, then just fill up the buffer */
		reserved_len = reserved_len>window->file_size?window->file_size:reserved_len;

		/* start to receive the packet, and unpack them */
		while (reserved_len > 0) {
			while ((reserved_len > 0) && (window->number_of_packet_in_window < WINDOW_SIZE)) {
				if (reserved_len >= DATA_SIZE) {
					if (recv_packet(window, 0) < 0) {
						fprintf(stderr, "receive packet failed\n");
						break;
					}

					if ((result = fetch_mesg(window, reserved_mesg, reserved_len)) < 0) {
						fprintf(stderr, "fetch message failed\n");
						break;
					}

					if (result != 0) {
						reserved_mesg += result;
						reserved_len -= result;
					}
				}
				else {
					if (recv_packet(window, 0) < 0) {
						fprintf(stderr, "receive packet failed\n");
						break;
					}

					if ((result = fetch_mesg(window, reserved_mesg, reserved_len)) < 0) {
						fprintf(stderr, "fetch message failed\n");
						break;
					}
					if (result != 0) {
						reserved_mesg += reserved_len;
						reserved_len = 0;
					}
				}
			}
		}

		/* DEBUG message */
		fprintf(stderr, "DEBUG window process\n");
		/* DEBUG message */

		/* finish the connection */
		four_way_handshake_r(window);

		return 0;
	}

	return -1;
}

/* create a socket and window, then bind them together to send the packet to initialize the connection with a seq_num */
int rsend(char* dest, int port, char* mesg, int len) {
	int socket_fd;
	socklen_t socket_len;
	struct hostent *hp;
	struct sockaddr_in* my_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
	struct sockaddr_in* serv_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));

	/* DEBUG message */
	fprintf(stderr, "DEBUG\n");
	/* DEBUG message */

	if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "socket failed\n");
		return -1;
	}

	bzero((char*)my_addr, sizeof(*my_addr));
	my_addr->sin_family = AF_INET;
	my_addr->sin_addr.s_addr = htonl(INADDR_ANY);
	my_addr->sin_port = htons(0);

	if (bind(socket_fd, (struct sockaddr*)my_addr, sizeof(*my_addr)) < 0) {
		fprintf(stderr, "bind error\n");
		return -1;
	}

	bzero((char*)serv_addr, sizeof(*serv_addr));
	serv_addr->sin_family = AF_INET;
	serv_addr->sin_port = htons(port);

	if ((hp = gethostbyname(dest)) == 0) {
		fprintf(stderr, "unknown address of %s\n", dest);
		return -1;
	}

	bcopy(hp->h_addr_list[0], (caddr_t)&serv_addr->sin_addr, hp->h_length);

	socket_len = sizeof(*serv_addr);

	/* window process prepare */
	struct uwindow* window;

	/* DEBUG message */
	fprintf(stderr, "DEBUG\n");

	//char buffer[100] = "12345";
	//sendto(socket_fd, buffer, 100, 0, (struct sockaddr*)serv_addr, socket_len);
	/* DEBUG message */

	window = new_window(socket_fd, my_addr, serv_addr);
	global_window = window;
	
	/* if the window_process returned the negative value, then do following */
	if (window_process(window, 1, mesg, len) < 0) {
		fprintf(stderr, "send message failed\n");
		rm_window(window);
		window = NULL;
		return -1;
	}

	/* if the return value is 0, then return 0 */
	rm_window(window);
	free(my_addr);
	free(serv_addr);
	window = NULL;
	close(socket_fd);
	return 0;
}

/* create a socket and window, then bind them together to recv the packet to initialize the connection with a seq_num */
int rrecv(int port, char* mesg, int len) {
	int socket_fd;
	int recv_len;
	socklen_t socket_len;
	struct sockaddr_in* my_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
	struct sockaddr_in* client_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
	
	/* DEBUG message */
	fprintf(stderr, "DEBUG\n");
	/* DEBUG message */

	if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "socket failed\n");
		return -1;
	}

	bzero((char*)my_addr, sizeof(*my_addr));
	my_addr->sin_family = AF_INET;
	my_addr->sin_addr.s_addr = htonl(INADDR_ANY);
	my_addr->sin_port = htons(port);

	if (bind(socket_fd, (struct sockaddr*)my_addr, sizeof(*my_addr)) < 0) {
		fprintf(stderr, "bind error\n");
		return -1;
	}

	socket_len = sizeof(*client_addr);

	/* window process prepare */
	struct uwindow* window;

	/* DEBUG message */
	fprintf(stderr, "DEBUG\n");
	/* DEBUG message */

	window = new_window(socket_fd, my_addr, client_addr);
	global_window = window;

	/* if the window_process returned the negative value, then do following */
	if (window_process(window, 0, mesg, len) < 0) {
		fprintf(stderr, "receive message failed\n");
		rm_window(window);
		window = NULL;
		return -1;
	}

	/* extract the length of the data */
	recv_len = window->file_size;

	/* if the return value is 0, then return 0, and mesg would contain the received data */
	rm_window(window);
	free(my_addr);
	free(client_addr);
	window = NULL;
	close(socket_fd);
	return recv_len;
}
