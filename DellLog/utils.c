


#include "utils.h"

#include <arpa/inet.h>


int check_securelevel(void) {
    int securelevel;
    size_t len = sizeof(securelevel);
    
    if (sysctlbyname("kern.securelevel", &securelevel, &len, NULL, 0) == 0) {
        return securelevel;
    }
    return -1;
}



int isIPAddr(char * str){
	uint32_t ip_num = inet_addr(str);
	if(ip_num == INADDR_NONE){
		return 0;
	}
	return 1;
}