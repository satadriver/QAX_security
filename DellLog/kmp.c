

#include "kmp.h"

void KmpGetNext(char* p, int next[])
{
	int pLen = strlen(p);
	memset(next,0,256);
	next[0] = -1;
	int k = -1;
	int j = 0;
	while (j < pLen - 1)
	{
		//p[k] is prefix，p[j] is surfix
		if (k == -1 || p[j] == p[k])
		{
			++k;
			++j;
			next[j] = k;
		}
		else
		{
			k = next[k];
		}
	}
}



int KmpSearch(char* s, int sLen,char* p,int pLen,int * next)
{
	int i = 0;
	int j = 0;

	while (i < sLen && j < pLen)
	{
		if (j == -1 || s[i] == p[j])
		{
			i++;
			j++;
		}
		else
		{  
			j = next[j];
		}
	}
	if (j == pLen)
		return i - j;
	else
		return -1;
}