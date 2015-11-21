#include "rudp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
	char mesg[50000];
	int recv_len = 0;
	FILE* ptr;

	ptr = fopen("o.txt", "w");
	recv_len = rrecv(9999, mesg, 50000);
	fprintf(stderr, "%d\n", recv_len);
	fwrite(mesg, sizeof(char), recv_len, ptr);

	fclose(ptr);
	return 0;
}
