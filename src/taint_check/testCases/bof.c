#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char *get_input(char *key)
{
	char *buffer = (char *)malloc(0x100);
	gets(buffer);
	return buffer;
}

int main(int argc, char **argv)
{
	char *res, *input;
	char dest[0x100];
	res = get_input("stdin");
	input = strdup(res);
	if (strlen(input) <= 0x200) {
		strcpy(dest, input);
	} else {
		printf("overflow!\n");
	}
	return 0;
}
