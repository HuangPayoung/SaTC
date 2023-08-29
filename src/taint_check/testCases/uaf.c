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
	char *dest;
	res = get_input("stdin");
	input = strdup(res);
	dest = (char *)malloc(0x100);
	free(dest);
	if (strlen(input) <= 0x200) {
		strcpy(dest, input);
	} else {
		printf("overflow!\n");
	}
	return 0;
}
