

#include <Windows.h>
#include <stdio.h>

#include "LogFlagEditor.h"

#include "LogClient.h"

#include "LoggerDll.h"
#include "pe.h"


int LogFlagEditor_Function1(HMODULE hbase, DWORD offset, CHAR* funptr) {
	int result = 0;

	DWORD function = (DWORD)((DWORD)hbase + offset);

	wchar_t wszport[256] = { 0 };
	wcscpy(wszport, RPC_SERVER_PORT);
	const wchar_t* protocol_sequence = L"ncacn_ip_tcp";
	const wchar_t* network_address = RPC_SERVER_IP;

	__asm {
		lea eax, wszport
		push eax
		push protocol_sequence
		push network_address
		mov ecx, funptr
		mov eax, function
		call eax
		//add esp, 12
		mov result, eax
	}

	if (funptr[1] == 0) 
	{
		__asm {
			push 1
			mov ecx, funptr

			mov eax, funptr
			mov eax, [eax]
			mov eax, [eax]
			call eax
		}

	}

	return 0;
}


int LogFlagEditor_Function2(HMODULE hbase, DWORD offset, CHAR* funptr) {
	int result = 0;

	DWORD function = (DWORD)((DWORD)hbase + offset);

	wchar_t wszport[256] = { 0 };
	wcscpy(wszport, RPC_SERVER_PORT);
	const wchar_t* protocol_sequence = L"ncacn_ip_tcp";
	const wchar_t* network_address = RPC_SERVER_IP;

	__asm {
		lea eax, wszport
		push eax
		push protocol_sequence
		push network_address
		mov ecx, funptr
		mov eax, function
		call eax
		//add esp, 12
		mov result, eax
	}

	if (funptr[1] == 0)
	{
		__asm {
			push 1
			mov ecx, funptr

			mov eax, funptr
			mov eax, [eax]
			mov eax, [eax]
			call eax
		}

	}else{
		__asm {	
			mov edx, funptr
			add edx,8

			push edx

			mov eax, funptr
			add eax,8
			mov ecx, [eax]

			mov eax, [eax]
			add eax,24
			mov eax, [eax]
			call eax
		}
	}

	return 0;
}

int LogFlagEditor() {
	int result = 0;

	char* hexe = 0;
	LoadPeFile((char*)"LogFlagEditor.exe",& hexe);
	char* func_ptr1 = new char[0x1024];

	LogFlagEditor_Function1((HMODULE)hexe, 0x983B, func_ptr1);

	char* func_ptr2 = new char[0x1024];
	LogFlagEditor_Function2((HMODULE)hexe, 0x99d1, func_ptr2);
	return 0;
}


