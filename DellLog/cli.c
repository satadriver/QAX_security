


#include "cli.h"


int SetLogServer(char * ipstr){
	
	char cmds[1024];

	char * format = "echo -e \"config\\n logging %s\\n end\\n \" | /f10/clish";
	
	int len = sprintf(cmds,format,ipstr);
	
	//printf("%s command:%s\r\n",__FUNCTION__,cmds);
	
	return system(cmds);
}


int RemoveLogServer(char * ipstr){
	
	char cmds[1024];

	char * format = "echo -e \"config\\n no logging %s\\n end\\n \" | /f10/clish";
	
	int len = sprintf(cmds,format,ipstr);
	
	//printf("%s command:%s\r\n",__FUNCTION__,cmds);
	
	return system(cmds);
}


int SetLogOn(){
	char * cmds ="echo -e \"config\\n logging on\\n end\\n \" | /f10/clish";
	//printf("%s command:%s\r\n",__FUNCTION__,cmds);
	return system(cmds);
}


int SetLogOff(){
	
	char * cmds = "echo -e \"config\\n no logging on\\n end\\n \" | /f10/clish";
	//printf("%s command:%s\r\n",__FUNCTION__,cmds);
	return system(cmds);
}


int EraseLog(){
	//char * cmds ="/f10/clish -c \"clear logging\"";
	char * cmds ="echo -e \"clear logging\\n y\" | /f10/clish";
	//printf("%s command:%s\r\n",__FUNCTION__,cmds);
	return system(cmds);
}


int CliCommand(char * cmd){
	
	return 0;
}
