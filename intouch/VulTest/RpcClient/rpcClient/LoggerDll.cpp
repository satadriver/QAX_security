
#include <Windows.h>
#include "LoggerDll.h"
#include <stdio.h>
#include <rpcdce.h>

typedef int (*sub_1000121F)(DWORD*,const wchar_t *,const wchar_t *,DWORD*);
typedef int (*sub_1000121F_1)(DWORD*, DWORD,DWORD, DWORD,DWORD,DWORD*);


typedef int (*sub_100022F3)(char* thisptr, int);
typedef int (*sub_10001f73)(char* thisptr);


typedef int (*sub_10006CFF)();




void Function1(HMODULE hdll) {
	int result = 0;

	char path[MAX_PATH];
	int pathlen = GetCurrentDirectoryA(MAX_PATH, path);

	DWORD* func_ptr = (DWORD*)new DWORD[16];
	memset(func_ptr, 0, 16 * sizeof(DWORD));

	DWORD function_1 = (DWORD)((DWORD)hdll + 0x121f);
	
	wchar_t wszport[256] = { 0 };
	wcscpy(wszport, RPC_SERVER_PORT);
	const wchar_t* protocol_sequence = L"ncacn_ip_tcp";
	const wchar_t* network_address = RPC_SERVER_IP;

	__asm {
		lea eax, wszport
		push eax
		push protocol_sequence
		push network_address
		mov ecx, func_ptr
		call function_1
		//add esp, 12
		mov result, eax
	}

	handle_t binding_handle = *(handle_t*)wszport;

	//func_ptr[0] = 0xe7a463;
	//func_ptr[1] = 0xe7a463;
	DWORD* function_base = (DWORD*)func_ptr[2];
	sub_1000121F_1 function_2 = (sub_1000121F_1)((DWORD)function_base[1]);
	__asm {
		lea eax, path
		push eax

		push 0
		push pathlen
		push 0
		push pathlen

		mov eax, func_ptr
		add eax, 8
		push eax

		mov ecx, func_ptr

		mov eax, function_2
		call eax
		//add esp, 24
		mov result, eax
	}

	__asm {
		push 1
		mov ecx, func_ptr
		mov eax,[ecx]
		mov eax,[eax]
		call eax
	}
}

void Function4(HMODULE hdll) {
	int result = 0;
	DWORD function_1 = (DWORD)((DWORD)hdll + 0x27ee);
	DWORD* func_ptr = (DWORD*)new DWORD[256];
	memset(func_ptr, 0, 256 * sizeof(DWORD));

	wchar_t wszport[256] = { 0 };
	wcscpy(wszport, RPC_SERVER_PORT);

	//wchar_t** lpszport = (wchar_t**)((DWORD)hdll + 0x939c);
	
	wchar_t* lpszport = (wchar_t*)((DWORD)hdll + 0x939c);
	DWORD dwOldProtect = 0;
	if (VirtualProtect((LPVOID)lpszport, sizeof(lpszport), PAGE_READWRITE, &dwOldProtect)) {
		
		//*lpszport = wszport;
		
		wcscpy(lpszport, RPC_SERVER_PORT);
		VirtualProtect((LPVOID)lpszport, sizeof(lpszport), dwOldProtect, &dwOldProtect);
	}
	else {
		printf("–ﬁ∏ƒƒ⁄¥Ê Ù–‘ ß∞‹£°\n");
	}

	__asm {
		mov ecx, func_ptr
		mov eax, function_1
		call eax
		mov result,eax
	}
}



void Function2(HMODULE hdll) {
	int result = 0;

	DWORD* func_ptr = (DWORD*)new DWORD[16];
	memset(func_ptr, 0, 16 * sizeof(DWORD));

	DWORD function_1 = (DWORD)((DWORD)hdll + 0x22f3);

	wchar_t wszport[256] = { 0 };
	wcscpy(wszport, RPC_SERVER_PORT);
	const wchar_t* protocol_sequence = L"ncacn_ip_tcp";
	const wchar_t* network_address = RPC_SERVER_IP;

	__asm {
		lea eax, wszport
		push eax
		push protocol_sequence
		push network_address
		mov ecx, func_ptr
		call function_1
		add esp, 12
		mov result, eax
	}

	int param[0x100] = { 0 };
	param[51] =(DWORD) func_ptr;
	if (func_ptr[1]) {
		param[50] = (DWORD)&func_ptr[2];
	}
	else {
		DWORD function_2 = (DWORD)((DWORD)hdll + 0x1f73);
		__asm {
			lea ecx, param
			mov eax, function_2
			call eax
		}
	}

	/*
	DWORD* function_base = (DWORD*)func_ptr[0];
	DWORD function_2 = (DWORD)((DWORD)function_base[0]);
	__asm {
		mov ecx, func_ptr
		lea eax,param
		push eax
		push eax
		push 1
		mov eax, function_2
		call eax
		add esp, 4
		mov result, eax
	}
	*/
}



void Function3(HMODULE hdll) {
	int result = 0;

	DWORD* func_ptr = (DWORD*)new DWORD[16];
	memset(func_ptr, 0, 16 * sizeof(DWORD));

	DWORD function_1 = (DWORD)((DWORD)hdll + 0x6cff);

	wchar_t wszport[256] = { 0 };
	wcscpy(wszport, RPC_SERVER_PORT);
	const wchar_t* protocol_sequence = L"ncacn_ip_tcp";
	const wchar_t* network_address = RPC_SERVER_IP;

	__asm {
		lea eax, wszport
		push eax
		push protocol_sequence
		push network_address
		mov ecx, func_ptr
		call function_1
		add esp, 12
		mov result, eax
	}

	int param[0x100] = { 0 };

	DWORD* function_base = (DWORD*)func_ptr[2];
	DWORD function_2 = (DWORD)((DWORD)function_base[0]);
	__asm {
		mov ecx, func_ptr

		lea eax,param
		push eax

		mov eax, func_ptr
		add eax,8
		push eax

		mov eax, function_2
		call eax

		//add esp, 8
		mov result, eax
	}

	function_base = (DWORD*)func_ptr[2];
	function_2 = (DWORD)((DWORD)function_base[1]);
	__asm {
		mov ecx, func_ptr

		lea eax, param
		push eax

		mov eax, func_ptr
		add eax, 8
		push eax

		mov eax, function_2
		call eax

		//add esp, 8
		mov result, eax
	}
}


int LoggerDll() {

	HMODULE hm = LoadLibraryA("msvcr100.dll");
	HMODULE hmp = LoadLibraryA("msvcp100.dll");	
	HMODULE hdll = LoadLibraryA("LoggerDLL.dll");
	if (hdll == NULL) {
		printf("Failed to load the DLL. Error code: %lu\n", GetLastError());
		return 1;
	}

	Function1(hdll);

	Function2(hdll);

	Function3(hdll);

	Function4(hdll);

	return 0;
}