#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{

	int target = 1;
	//printf("%d\n", argc);
	if(argc >= 2)
			target = strtol(argv[1], NULL, 10);

    //for (int i = 0; i < 12; i++) {
    for (int i = 0; i < target; i++) {
        fork();
        //printf("(%ld)(%ld)(%d)-\n", (long)getpid(), (long)getppid(), i);                         
        printf("-");                         
    }

    fflush(stdout);
    return 0;
}
