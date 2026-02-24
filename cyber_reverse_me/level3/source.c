#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void ok()
{
	puts("Good job.");
}

void no()
{
	puts("Nope.");
	exit(1);
}

int main()
{
	char input[24];
	int arg_count = 0;

	printf("Please enter key: ");
	fflush(stdout);

	arg_count = scanf("%23s", input);

	if (arg_count != 1)
		no();
	
	if (input[1] != '2')
		no();

	if (input[0] != '4')
		no();

	char buffer[9];
	memset(buffer, 0, 9);
	buffer[0] = '*';

	char temp[4];
	temp[3] = '\0';
	int i = 2;
	int j = 1;

	while (strlen(buffer) < 8 && i < strlen(input))
	{
		strncpy(temp, &input[i], 3);
		buffer[j] = atoi(temp);
		j++;
		i+=3;
	}

	if (!strcmp(buffer,"********"))
		ok();
	else
		no();

	return 0;
}
