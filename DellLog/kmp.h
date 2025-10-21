

#include <stdio.h>
#include <stdlib.h>
#include <string.h>



int KmpSearch(char* s, int slen,char* p,int plen,int * next);


void KmpGetNext(char* p, int next[]);