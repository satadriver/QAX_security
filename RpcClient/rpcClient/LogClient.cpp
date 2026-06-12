
#include <Windows.h>
#include "LogClient.h"
#include <stdio.h>
#include <rpcdce.h>
#include "LoggerDll.h"


typedef void* (*ptrmalloc)(int size);





void LogClient_Function0(HMODULE hdll,DWORD offset, char * funptr,char * uuid,char *struuid) {
	int result = 0;

	DWORD function_1 = (DWORD)((DWORD)hdll + offset);

	wchar_t wszport[256] = { 0 };
	wcscpy(wszport, RPC_SERVER_PORT);
	const wchar_t* protocol_sequence = L"ncacn_ip_tcp";
	const wchar_t* network_address = RPC_SERVER_IP;

	__asm {
		lea eax, wszport
		push eax
		push protocol_sequence
		push network_address
		push struuid
		push uuid

		mov ecx, funptr
		call function_1
		//add esp, 12
		mov result, eax
	}

	return;
}


int LogClient_Function1(HMODULE hdll,DWORD offset, CHAR* funptr) {
	int result = 0;

	DWORD function = (DWORD)((DWORD)hdll + offset);

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

	if (funptr[1] == 0) {
		__asm {
			push 1
			mov ecx, funptr

			mov eax, funptr
			mov eax, [eax]
			mov eax, [eax]
			call eax
		}

		return 1;
	}

	return 0;
}


int LogClient() {
	int result = 0;
	HMODULE hdll = LoadLibraryA("LogClient.dll");
	if (hdll == NULL) {
		printf("Failed to load the DLL. Error code: %lu\n", GetLastError());
		return 1;
	}

	ptrmalloc mymalloc = (ptrmalloc)((char*)hdll + 0xF0DC);

	//this + 32
	{
		DWORD* func_ptr = (DWORD*)mymalloc(sizeof(char*) * 16);
		char* uuid = (char*)hdll + 0x19F09C;
		char* struuid = (char*)hdll + 0x14F478;
		LogClient_Function0(hdll, 0xa860, (char*)func_ptr, uuid, struuid);

		func_ptr[2] = (DWORD)hdll + 0x14F2A0;
		func_ptr[0] = (DWORD)hdll + 0x14F428;
		func_ptr[2] = (DWORD)hdll + 0x14F430;

		if (func_ptr[1] == 0) {
			__asm {
				push 1
				mov ecx, func_ptr

				mov eax, func_ptr
				mov eax, [eax]
				mov eax, [eax]
				call eax
			}

			//this + 28
			{
				DWORD* func_ptr1 = (DWORD*)mymalloc(sizeof(char*) * 16);
				result = LogClient_Function1(hdll, 0xa640, (char*)func_ptr1);
				if (result) {
					//this + 24
					{

						DWORD* func_ptr2 = (DWORD*)mymalloc(sizeof(char*) * 16);
						LogClient_Function1(hdll, 0xa680, (char*)func_ptr2);
					}
				}
			}



		}
	}

	//this + 44
	{
		DWORD* func_ptr3 = (DWORD*)mymalloc(sizeof(char*) * 16);
		char* uuid2 = (char*)hdll + 0x19F0bC;
		char* struuid2 = (char*)hdll + 0x14F5B0;
		LogClient_Function0(hdll, 0xa860, (char*)func_ptr3, uuid2, struuid2);

		func_ptr3[2] = (DWORD)hdll + 0x14F4E4;
		func_ptr3[0] = (DWORD)hdll + 0x14F580;
		func_ptr3[2] = (DWORD)hdll + 0x14F588;

		if (func_ptr3[1] == 0) {
			__asm {
				push 1
				mov ecx, func_ptr3

				mov eax, func_ptr3
				mov eax, [eax]
				mov eax, [eax]
				call eax
			}
			//this + 36
			{
				DWORD* func_ptr4 = (DWORD*)mymalloc(sizeof(char*) * 16);
				LogClient_Function1(hdll, 0xa600, (char*)func_ptr4);
			}

		}

	}

	printf("hello world!\r\n");
	return 0;
}