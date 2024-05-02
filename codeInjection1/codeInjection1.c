#include <stdio.h>

void printMess(const char* buff)
{
	printf("%s\n", buff);
}

int main()
{
    char* buffer = "hello world";
    while (1)
    {
        getchar();
        printMess(buffer);
    }
	return 0;
}