


#include "utils.h"

#include "kvm.h"

#include "mem.h"

#include "cli.h"

//gcc -w -static ./dellLog.c -o ./dellLog -lkvm |more


int test(int argc,char ** argv){
	
	struct proc processinfo;
	pid_t pid = (pid_t) atoi(argv[1]);
	
	get_proc_vm_regions(pid);
	get_proc_by_pid_kvmprocs(pid,&processinfo);
	find_proc_by_pid(pid,&processinfo);
	
	return 0;
}

int main (int argc,char ** argv){

	int ret = 0;
	
	int privilige = check_securelevel();
	printf("priv:%d\r\n",privilige);
	
	int ch = 0;
	
	while ((ch = getopt(argc, argv, "d::ecos:")) != -1)
	{
        printf("optind: %d\n", optind);
        switch (ch) 
        {
			case 'c':
			{
				printf("close log\r\n");
				ret = SetLogOff();
				break;
			}		
			case 'e':
			{
				printf("erase log\r\n");
				ret = EraseLog();
				break;
			}
			case 'o':
			{
				printf("open log\r\n");
				ret = SetLogOn();
				break;
			}
			case 's':
			{
				char * server = optarg;
				printf("server: %s\n", server);
				ret = SetLogServer(server);
				break;
			}
			case 'd':
			{	
				char * param = optarg;
				printf("delete logging with arg:%s\r\n",param);
				ret = isIPAddr(param);
				if(ret){
					DeleteAddr(param);
				}
				else{
					DeleteUser(param);
				}
				
				break;
			}
			default:
			{
				break;
			}
		}	
	}
	
	return ret;
}
