#include "rudp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
	int len = 5000;
	char buffer[50000] = {};
	FILE *ptr, *local;

	ptr = fopen("i.txt", "r");
	local = fopen("lo.txt", "w");
	fread(buffer, sizeof(char), len, ptr);
	fwrite(buffer, sizeof(char), len, local);

	rsend("127.0.0.1", 9999, buffer, len);

	fclose(ptr);
	return 0;
}
