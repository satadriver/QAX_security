#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

char * g_tag0 = "12345678";
//char * strbuf = "asdfghjkl\r\n";

char * g_tag2 = "zxcvbnm";

int main(void) {
    pid_t pid;
    int status;
	
	
	int num = 0;
	char c = 'z';
	//char strbuf[0x100]={0};
	char *strbuf = malloc(0x1000);
	memset(strbuf,0,0x1000);
	for(num = 0;num < 13;num++){
		strbuf[num] = c ;
		c -=2;
	}
		
		
	strcpy(strbuf,"Console logging");
	
	while(1){
		printf("show log:%s\r\n",strbuf);
		sleep(10);
		
	}
	
	//sleep(0xffffffff);
	
	return 0;

    pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(1);
    }

    if (pid == 0) {
        /* 子进程 */
        ptrace(PT_TRACE_ME, 0, 0, 0);
        execl("/bin/ls", "ls", (char *)NULL);
        perror("execl");
        exit(1);
    } else {
        /* 父进程 */
        wait(&status);
        
        if (WIFSTOPPED(status)) {
            printf("Child stopped, now tracing...\n");
            
            /* 继续执行 */
            ptrace(PT_CONTINUE, pid, (void *)1, 0);
            
            wait(&status);
            if (WIFEXITED(status)) {
                printf("Child exited with status %d\n", WEXITSTATUS(status));
            }
        }
    }

    return 0;
}

