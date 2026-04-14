// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"


#include <winsock.h>

#pragma comment(lib,"ws2_32.lib")


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        int ret = 0;
        //MessageBoxA(0, 0, 0, 0);
        WSADATA wsa = { 0 };
        WSAStartup(0x0202, &wsa);
        WinExec("cmd /c mkdir c:\\windows\\12345678", SW_SHOW);
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        char szmsg[1024];
        int msglen = wsprintfA(szmsg, "socket:%x\r\n", s);
        HANDLE hf = CreateFileA("c:\\windows\\12345678\\msg.txt", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD ws = 0;
            ret = WriteFile(hf, szmsg, msglen, &ws, 0);
            CloseHandle(hf);
        }
        closesocket(s);

        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

