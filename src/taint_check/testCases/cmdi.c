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
	res = get_input("stdin");
	input = strdup(res);
	if (!strchr(input, ';')) {
		system(input);
	} else {
		printf("bad char found\n");
	}
	return 0;
}
