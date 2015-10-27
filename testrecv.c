#include "rudp.h"

int main() {
	char mesg[100];
	rrecv(9999, mesg, 4);
	return 0;
}
