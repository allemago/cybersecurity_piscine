#include <string.h>
#include <stdio.h>

int main()
{
	char buffer[80];

	printf("Please enter key: ");
	fflush(stdout);

	scanf("%s", buffer);

	if (strcmp("__stack_check", buffer))
	{
		printf("Nope.\n");
		return 1;
	}

	printf("Good job.\n");
	
	return 0;
}
