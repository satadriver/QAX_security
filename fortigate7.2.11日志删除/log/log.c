

#ifdef _WIN32

#include <Windows.h>
//#include <iostream>
#include <stdio.h>

struct iovec {
	unsigned long long iov_base; /* 指向数据缓冲区的起始地址 */
	unsigned long long iov_len;  /* 该缓冲区的长度（字节数） */
};

#define  socklen_t  unsigned long long

#define size_t unsigned long long

struct msghdr {
	void* msg_name;					// 可选：目标地址（用于未连接的套接字）
	socklen_t     msg_namelen;		// 地址长度
	struct iovec* msg_iov;			// 分散/聚集 I/O 的缓冲区数组
	size_t        msg_iovlen;		// 缓冲区数组的元素个数
	void* msg_control;				// 辅助数据（控制信息）的起始地址
	size_t        msg_controllen;	// 辅助数据的长度
	int           msg_flags;		// 调用时的标志（通常忽略，由 recvmsg 使用）
};

#else
#include <stdio.h>
#include <sys/socket.h>    // msghdr 定义在此
#include <sys/uio.h>       // struct iovec（msghdr 成员依赖）

#include <fcntl.h>      // open, O_* 常量
#include <unistd.h>     // write, close
#include <errno.h>      // errno
#include <string.h>     // strerror

#define DWORD unsigned int
#define __int64 long long
#endif

#define _QWORD unsigned long long
#define _DWORD unsigned int
#define _BYTE unsigned char
#define __int8  char



#define FUNC1_CODE1_SIZE		0
#define FUNC1_CODE2_SIZE		0X800
#define FUNC2_CODE1_SIZE		0X100
#define FUNC2_CODE2_SIZE		0X800





#ifdef _WIN32

#else
__attribute__((aligned(256)))
#endif
unsigned long long new_11910A0(char * a1,char * a2,int a3)   {
	
	//typedef int (*ptr_function)(char* a1, char* a2, int a3);
	typedef int (*ptr_fflush)(FILE* stream);
	typedef size_t(*ptr_fwrite)(const void* ptr, size_t size, size_t n, FILE* s);
	typedef int (*ptrfseek)(FILE* stream, unsigned long long off, int whence);

	char* regrip = 0;
#ifdef _WIN32

#else
	__asm__ volatile("lea 0(%%rip), %0" : "=r"(regrip));
#endif
	unsigned long long* baseptr = (unsigned long long*) (((unsigned long long)regrip & 0xffffffffff00) - 0x10);
	unsigned long long baseaddr = *baseptr;

	char* fwrite_addr = *(char**)0x42945B8;
	char* fflush_addr = *(char**)0x4293020;
	char* fseek_addr = *(char**)0x4294878;
	char* databuf = (char*)0x2CAB800;

	//databuf + 0:						code of replacement
	//databuf + FIRST_CODECHUNK_SIZE - 0x10 :			base
	//databuf + FIRST_CODECHUNK_SIZE :					code
	//databuf + FIRST_CODECHUNK_SIZE + SECOND_CODECHUNK_SIZE:			new code address
	//databuf + FIRST_CODECHUNK_SIZE + SECOND_CODECHUNK_SIZE + 0x10:	format string

	char* lpformat = (char*)(databuf + FUNC1_CODE1_SIZE + FUNC1_CODE2_SIZE + 0x10);
	int counter = *(int*)lpformat;
	char* filter = lpformat + sizeof(int);

	char* hdr = (char*)(*(unsigned long long*)(a1 + 128));
	char* end = (char*)(*(unsigned long long*)(a1 + 136));
	int datasize = (int)(end - hdr);
	
	int found = 0;
	for (int num = 0; num < datasize; num++) {
		int cnt = 0;
		int n = num;
		char* key = filter;
		while (cnt < counter) {
			while (*key && *(key) == hdr[n]) {
				key++;
				n++;
			}
			if (*key) {
				while (*(key++)) {}
				cnt++;
				n = num;
			}
			else {
				found = 1;
				break;
			}
		}
		if (found)
			break;
	}

	FILE* file = *(FILE**)(a1 + 8);

	if (found == 0) {
		ptr_fwrite lpfwrite = (ptr_fwrite)fwrite_addr;
		ptr_fflush lpfflush = (ptr_fflush)fflush_addr;
		if (lpfwrite(&a3, 4uLL, 1uLL, file) == 1 && lpfwrite(a2, a3, 1uLL, file) == 1)
		{
			lpfflush(file);
			*(DWORD*)(a1 + 116) += a3 + 4;	
			return 0;
		}	
	}

	ptrfseek fs = (ptrfseek)fseek_addr;
	fs(file, *(unsigned int*)(a1 + 116), 0);
	return 1;
}



#ifdef _WIN32

#else
__attribute__((aligned(256)))
#endif
unsigned long long new_13CD960(char* a1, char* a2, int a3) {

	char* regrip = 0;
#ifdef _WIN32

#else
	__asm__ volatile("lea 0(%%rip), %0" : "=r"(regrip));
#endif

	unsigned long long* baseptr = (unsigned long long*) (((unsigned long long)regrip & 0xffffffffff00) - 0x10);
	unsigned long long baseaddr = *baseptr;

	//typedef int (*ptr_function)(char* a1, char* a2, int a3);
	typedef int (*ptr_fflush)(FILE* stream);
	typedef size_t(*ptr_fwrite)(const void* ptr, size_t size, size_t n, FILE* s);
	typedef int (*ptrfseek)(FILE* stream, unsigned long long off, int whence);
	typedef int (*ptr_fsync)(int fd);
	typedef int (*ptr_fileno)(FILE* stream);

	char* fsync_addr = *(char**)((char*)baseaddr + 0x4FEC090);
	char* fileno_addr = *(char**)((char*)baseaddr + 0x4FECD78);
	char* fwrite_addr = *(char**)((char*)0x4FECB30 + baseaddr);
	char* fflush_addr = *(char**)((char*)0x4FEB4D0 + baseaddr);
	char* fseek_addr = *(char**)((char*)0x4FECDE8 + baseaddr);

	char* databuf = (char*)0x465c00 + baseaddr;

	//databuf + 0:						code of replacement
	//databuf + FIRST_CODECHUNK_SIZE - 0x10 :			base
	//databuf + FIRST_CODECHUNK_SIZE :					code
	//databuf + FIRST_CODECHUNK_SIZE + SECOND_CODECHUNK_SIZE:			new target address
	//databuf + FIRST_CODECHUNK_SIZE + SECOND_CODECHUNK_SIZE + 0x10:	format string

	char* lpformat = (char*)(databuf + FUNC2_CODE1_SIZE + FUNC2_CODE2_SIZE + 0x10);
	int counter = *(int*)lpformat;
	char* filter = lpformat + sizeof(int);

	char* hdr = (char*)(*(unsigned long long*)(a1 + 128));
	char* end = (char*)(*(unsigned long long*)(a1 + 136));
	int datasize = (int)(end - hdr);

	int found = 0;
	for (int num = 0; num < datasize; num++) {
		int cnt = 0;
		int n = num;
		char* key = filter;
		while (cnt < counter) {
			while (*key && *(key) == hdr[n]) {
				key++;
				n++;
			}
			if (*key) {
				while (*(key++)) {}
				cnt++;
				n = num;
			}
			else {
				found = 1;
				break;
			}
		}
		if (found)
			break;
	}

	FILE* file = *(FILE**)(a1 + 8);

	if (found == 0) {
		ptr_fwrite lpwrite = (ptr_fwrite)fwrite_addr;
		ptr_fflush lpfflush = (ptr_fflush)fflush_addr;
		if (lpwrite(&a3, 4uLL, 1uLL, file) == 1 && lpwrite(a2, a3, 1uLL, file) == 1)
		{
			lpfflush(file);
			//"8B 05 76 3A AA 04": this code is relative address from current rip
			int* ptr =(int*) (0x5E71480 + baseaddr);
			if ( *ptr)
			{
				ptr_fileno lp_fileno = (ptr_fileno)fileno_addr;
				ptr_fsync lp_fsync = (ptr_fsync)(fsync_addr);
				int v5 = lp_fileno(*(FILE**)(a1 + 8));
				lp_fsync(v5);
			}
			*(DWORD*)(a1 + 116) += a3 + 4;
			return 0;
		}
	}

	ptrfseek fs = (ptrfseek)fseek_addr;
	fs(file, *(unsigned int*)(a1 + 116), 0);
	return 1;
}


#ifdef _WIN32

#else
__attribute__((aligned(256)))
#endif
int new_1191160(char * a1,int a2,int a3) {

	__int64 v4; // rax
	__int64 v6; // rbx
	__int64 v7; // rdi
	__int64 v8; // rdx
	__int64 result; // rax
	int v10; // eax
	int v11; // r15d
	int v12; // r8d
	int v13=0; // eax
	FILE* v14; // rcx
	__int64 v15; // r12
	__int64 v16; // rax
	_QWORD* v17; // rax
	unsigned int v18; // [rsp+Ch] [rbp-44h]
	__int64 ptr[8]; // [rsp+10h] [rbp-40h] BYREF

	typedef int (*ptr_fflush)(FILE* stream);
	typedef size_t(*ptr_fwrite)(const void* ptr, size_t size, size_t n, FILE* s);
	typedef int (*ptrfseek)(FILE* stream, unsigned long long off, int whence);
	char* fwrite_addr = *(char**)0x42945B8;
	char* fflush_addr = *(char**)0x4293020;
	ptr_fwrite lpfwrite = (ptr_fwrite)fwrite_addr;
	ptr_fflush lpfflush = (ptr_fflush)fflush_addr;

	typedef __int64 (*ptr_sub_2BBF6A0)(unsigned __int64 a1, _BYTE* a2, int a3);
	ptr_sub_2BBF6A0 sub_2BBF6A0 = (ptr_sub_2BBF6A0)0x2BBF6A0;
	typedef __int64 (*ptr_sub_11910A0)(__int64 a1, const void* a2, int a3);
	ptr_sub_11910A0 sub_11910A0 = (ptr_sub_11910A0)0x11910A0;
	typedef __int64 (* ptr_sub_2A16070)(__int64 a1, __int64 a2);
	ptr_sub_2A16070 sub_2A16070 = (ptr_sub_2A16070)0x2A16070;
	typedef void  (*ptr_sub_11970E0)(unsigned int a1, int a2);
	ptr_sub_11970E0 sub_11970E0 = (ptr_sub_11970E0)0x11970E0;
	typedef __int64* (*ptr_sub_2A02DB0)(int a1, int a2, int a3, int a4);
	ptr_sub_2A02DB0 sub_2A02DB0 = (ptr_sub_2A02DB0)0x2A02DB0;
	typedef __int64  (*ptr_sub_1193C40)(__int64 a1, FILE * a2);
	ptr_sub_1193C40 sub_1193C40 = (ptr_sub_1193C40)0x1193C40;
	typedef __int64  (*ptr_sub_29F3B50)(__int64* a1);
	ptr_sub_29F3B50 sub_29F3B50 = (ptr_sub_29F3B50)0x29F3B50;

	v4 = (unsigned long long)a1 + 10760;
	if (a3 == 1)
		v4 = (unsigned long long)a1 + 18584;
	v6 = v4 + 296LL * a2;
	v7 = *(_QWORD*)(v6 + 128);
	v8 = *(_QWORD*)(v6 + 136) - v7;
	result = (unsigned int)v8;

	if (*(_DWORD*)(v6 + 136) != (_DWORD)v7)
	{
		char* databuf = (char*)0x2CAB800;
		char* lpformat = (char*)(databuf + FUNC1_CODE1_SIZE + FUNC1_CODE2_SIZE + 0x10);
		int counter = *(int*)lpformat;
		char* filter = lpformat + sizeof(int);
		char* hdr = (char*)(*(unsigned long long*)(v6 + 128));
		char* end = (char*)(*(unsigned long long*)(v6 + 136));
		int datasize = (int)(end - hdr);
		int found = 0;
		for (int num = 0; num < datasize; num++) {
			int cnt = 0;
			int n = num;
			char* key = filter;
			while (cnt < counter) {
				while (*key && *(key) == hdr[n]) {
					key++;
					n++;
				}
				if (*key) {
					while (*(key++)) {}
					cnt++;
					n = num;
				}
				else {
					found = 1;
					break;
				}
			}
			if (found)
				break;
		}


#ifdef _WIN32

#else
		char filename[16];
		filename[0] = 't';
		filename[1] = 'e';
		filename[2] = 's';
		filename[3] = 't';
		filename[4] = 'l';
		filename[5] = 'o';
		filename[6] = 'g';
		filename[7] = 0;

		typedef int (*ptrclose)(int fd);
		typedef ssize_t(*ptrwrite)(int fd, const void* buf, size_t count);
		typedef int (*ptropen)(const char* pathname, int flags, mode_t mode);
		ptrwrite lpwrite = (ptrwrite) * (unsigned long long*)( 0x4296D60);
		ptropen lpopen = (ptropen) * (unsigned long long*)( 0x42957E0);
		ptrclose lpclose = (ptrclose) * (unsigned long long*)( 0x42950F0);

		// 1. 打开文件：若不存在则创建，若存在则追加写入
		int fd = lpopen(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
		// 2. 写入数据
		ssize_t bytes_written = lpwrite(fd, hdr, datasize);
		// 3. 关闭文件
		lpclose(fd);
#endif

		if (found == 0) {
			v10 = sub_2BBF6A0(v7, (_BYTE*)0x673E300, v8);
			v11 = v10;
			if (v10 <= 0)
			{
				v13 = 0;
			}
			else
			{
				v12 = sub_11910A0(v6, (const void*)0x673E300, v10);
				v13 = 0;
				if (!v12)
				{
					*(_DWORD*)(v6 + 120) = *(_DWORD*)(v6 + 112);
					if (a3 == 1)
						sub_2A16070(*(unsigned int*)(a1 + 36), v11 + 4LL);
					else
						sub_11970E0((unsigned int)a2, (unsigned int)(v11 + 4));
					sub_2A02DB0(*(unsigned int*)(a1 + 36), a3, (unsigned int)a2, (unsigned int)(v11 + 4));
					v14 = *(FILE**)(v6 + 24);
					ptr[0] = ((unsigned __int64)*(unsigned int*)(v6 + 116) << 34) | (16LL * (*(_DWORD*)(v6 + 112) & 0x3FFFFFFF)) | 1;
					if (v14)
					{
						lpfwrite(ptr, 8uLL, 1uLL, v14);
						lpfflush(*(FILE**)(v6 + 24));
					}
					v15 = 0LL;
					sub_1193C40(v6 + 168, (FILE*)*(_QWORD*)(v6 + 16));
					if (*(_BYTE*)(v6 + 32))
					{
						do
						{
							v16 = 7 * v15++;
							sub_1193C40(*(_QWORD*)(v6 + 40) + 8 * v16 + 16, (FILE*)*(_QWORD*)(*(_QWORD*)(v6 + 40) + 8 * v16 + 8));
						} while (*(__int8*)(v6 + 32) > (int)v15);
					}
					v17 = *(_QWORD**)(v6 + 288);
					if (v17)
						sub_1193C40((__int64)v17 + 2, (FILE*)*v17);
					v13 = 1;
				}
			}
		}
		else {
			char* fseek_addr = *(char**)0x4294878;
			ptrfseek fs = (ptrfseek)fseek_addr;
			FILE * fh = *(FILE**)(v6 + 8);
			fs(fh, *(unsigned int*)(v6 + 116), 0);
			v13 = 1;
		}
		v18 = v13;
		sub_29F3B50((__int64* )(v6 + 128));
		return v18;
	}
	return result;
}



#ifdef _WIN32

#else
__attribute__((aligned(256)))
#endif
__int64  new_13CDA40(__int64 a1, int a2, unsigned int a3)
{
	__int64 v3; // rax
	__int64 v6; // r12
	__int64 v7; // rdi
	__int64 v8; // rdx
	__int64 result; // rax
	int v10; // eax
	int v11; // r15d
	int v12; // r8d
	int v13; // eax
	__int64 v14; // rdi
	__int64 v15; // rbx
	__int64 v16; // rax
	FILE** v17; // rax
	unsigned int v18; // [rsp-3Ch] [rbp-3Ch]

	char* regrip = 0;
#ifdef _WIN32

#else
	__asm__ volatile("lea 0(%%rip), %0" : "=r"(regrip));
#endif

	unsigned long long* baseptr = (unsigned long long*) (((unsigned long long)regrip & 0xffffffffff00) - 0x10);
	unsigned long long baseaddr = *baseptr;

	typedef __int64  (*ptr_sub_31D5E10)(__int64 a1, __int64 a2, int a3);
	ptr_sub_31D5E10 sub_31D5E10 = (ptr_sub_31D5E10)(baseaddr+0x31D5E10);
	typedef __int64  (*ptr_sub_13CD960)(__int64 a1, const void* a2, int a3);
	ptr_sub_13CD960 sub_13CD960 = (ptr_sub_13CD960)(baseaddr + 0x13CD960);
	typedef __int64  (*ptr_sub_2FF3B50)(__int64 a1, __int64 a2);
	ptr_sub_2FF3B50 sub_2FF3B50 = (ptr_sub_2FF3B50)(baseaddr + 0x2FF3B50);
	typedef void  (*ptr_sub_13D4080)(unsigned int a1, int a2);
	ptr_sub_13D4080 sub_13D4080 = (ptr_sub_13D4080)(baseaddr + 0x13D4080);
	typedef __int64* (*ptr_sub_2FE0C60)(int a1, int a2, int a3, int a4);
	ptr_sub_2FE0C60 sub_2FE0C60 = (ptr_sub_2FE0C60)(baseaddr + 0x2FE0C60);
	typedef __int64 (*ptr_sub_13CD8C0)(__int64 a1);
	ptr_sub_13CD8C0 sub_13CD8C0 = (ptr_sub_13CD8C0)(baseaddr + 0x13CD8C0);
	typedef void (*ptr_sub_13D0750)(__int64 a1, FILE * a2);
	ptr_sub_13D0750 sub_13D0750 = (ptr_sub_13D0750)(baseaddr + 0x13D0750);
	typedef __int64 (*ptr_sub_2FD33F0)(__int64* a1);
	ptr_sub_2FD33F0 sub_2FD33F0 = (ptr_sub_2FD33F0)(baseaddr + 0x2FD33F0);

	v3 = a1 + 9968;
	if (a3 == 1)
		v3 = a1 + 18400;
	v6 = v3 + 296LL * a2;
	v7 = *(_QWORD*)(v6 + 128);
	v8 = *(_QWORD*)(v6 + 136) - v7;
	result = (unsigned int)v8;

	if (*(_DWORD*)(v6 + 136) != (_DWORD)v7)
	{
		char* databuf = (char*)baseptr + 0x465c00;
		char* lpformat = (char*)(databuf + FUNC2_CODE1_SIZE + FUNC2_CODE2_SIZE + 0x10);
		int counter = *(int*)lpformat;
		char* filter = lpformat + sizeof(int);
		char* hdr = (char*)(*(unsigned long long*)(v6 + 128));
		char* end = (char*)(*(unsigned long long*)(v6 + 136));
		int datasize = (int)(end - hdr);
		int found = 0;
		for (int num = 0; num < datasize; num++) {
			int cnt = 0;
			int n = num;
			char* key = filter;
			while (cnt < counter) {
				while (*key && *(key) == hdr[n]) {
					key++;
					n++;
				}
				if (*key) {
					while (*(key++)) {}
					cnt++;
					n = num;
				}
				else {
					found = 1;
					break;
				}
			}
			if (found)
				break;
		}


#ifdef _WIN32

#else
		char filename[16];
		filename[0] = 't';
		filename[1] = 'e';
		filename[2] = 's';
		filename[3] = 't';
		filename[4] = 'l';
		filename[5] = 'o';
		filename[6] = 'g';
		filename[7] = 0;

		typedef int (* ptrclose)(int fd);
		typedef ssize_t (*ptrwrite)(int fd, const void* buf, size_t count);
		typedef int (*ptropen)(const char* pathname, int flags, mode_t mode);
		ptrwrite lpwrite = (ptrwrite)*(unsigned long long*)(baseaddr + 0x4FEF468);
		ptropen lpopen = (ptropen) * (unsigned long long*)(baseaddr + 0x4FEDDD8);
		ptrclose lpclose = (ptrclose) * (unsigned long long*)(baseaddr + 0x4FED690);
		
		// 1. 打开文件：若不存在则创建，若存在则追加写入
		int fd = lpopen(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
		// 2. 写入数据
		ssize_t bytes_written = lpwrite(fd, hdr, datasize);
		// 3. 关闭文件
		lpclose(fd);
#endif

		if (found == 0) {
			v10 = sub_31D5E10(v7, (__int64)(baseaddr + 0x5E71580), v8);
			v11 = v10;
			if (v10 <= 0)
			{
				v13 = 0;
			}
			else
			{
				v12 = sub_13CD960(v6, (const void*)(baseaddr + 0x5E71580), v10);
				v13 = 0;
				if (!v12)
				{
					*(_DWORD*)(v6 + 120) = *(_DWORD*)(v6 + 112);
					if (a3 == 1)
						sub_2FF3B50(*(unsigned int*)(a1 + 36), v11 + 4LL);
					else
						sub_13D4080((unsigned int)a2, (unsigned int)(v11 + 4));
					v14 = *(unsigned int*)(a1 + 36);
					v15 = 0LL;
					sub_2FE0C60(v14, a3, (unsigned int)a2, (unsigned int)(v11 + 4));
					sub_13CD8C0(v6);
					sub_13D0750(v6 + 168, *(FILE**)(v6 + 16));
					if (*(_BYTE*)(v6 + 32))
					{
						do
						{
							v16 = 7 * v15++;
							sub_13D0750(*(_QWORD*)(v6 + 40) + 8 * v16 + 16, *(FILE**)(*(_QWORD*)(v6 + 40) + 8 * v16 + 8));
						} while (*(__int8*)(v6 + 32) > (int)v15);
					}
					v17 = *(FILE***)(v6 + 288);
					if (v17)
						sub_13D0750((__int64)(v17 + 2), *v17);
					v13 = 1;
				}
			}
		}
		else {
			char* fseek_addr = *(char**)((char*)0x4FECDE8 + baseaddr);
			typedef int (*ptrfseek)(FILE* stream, unsigned long long off, int whence);
			ptrfseek fs = (ptrfseek)fseek_addr;
			FILE* fh = *(FILE**)(v6 + 8);
			fs(fh, *(unsigned int*)(v6 + 116), 0);
			v13 = 1;
		}
		v18 = v13;
		sub_2FD33F0((__int64* )(v6 + 128));
		return v18;
	}
	return result;
}


#ifdef _WIN32

#else
__attribute__((aligned(256)))
#endif
int codesize(int fd, struct msghdr* msg, int size) {

	unsigned int total = 0;
	struct iovec* buf = msg->msg_iov;
	unsigned long long cnt = msg->msg_iovlen;
	for (int i = 0; i < (int)cnt; i++) {
		total += buf[i].iov_len;
	}
	return total;
}



#ifdef _WIN32

#else
__attribute__((aligned(256)))
#endif
void codtest(char * lpformat,int datasize,char * hdr) {
	int counter = *(int*)lpformat;
	int found = 0;
	char* filter = lpformat + sizeof(int);
	for (int num = 0; num < datasize; num++) {
		int cnt = 0;
		int n = num;
		char* key = filter;
		while (cnt < counter) {
			while (*key && *(key) == hdr[n]) {
				key++;
				n++;
			}
			if (*key) {
				while (*(key++)) {}
				cnt++;
				n = num;
			}
			else {
				found = 1;
				break;
			}
		}
		if (found)
			break;
	}
}



int main(int argc,char ** argv) {
	char* param = argv[1];
	char* param2 = argv[2];
	char* param3 = argv[3];
	printf("param:%s,param2:%s,param3:%s\r\n",param,param2,param3);
	int ret = 0;

#ifdef _WIN32
	HANDLE hf = CreateFileA("log.txt", GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	int fs = GetFileSize(hf, NULL);

	char* buf = malloc(fs+0x1000);

	DWORD rs = 0;
	ret = ReadFile(hf, buf, fs, &rs, NULL);
	CloseHandle(hf);
	char format[0x100] = { 0 };

	*(int*)format = 2;
	const char* name[2] = { "System performance statistics1","System performance statistics" };
	lstrcpyA(format + 4, name[0]);

	lstrcpyA(format + 4 + lstrlenA(name[0]) + 1, name[1]);

	codtest(format, fs, buf);
	return 0;

	new_11910A0((char*)buf, 0, 0);
	new_13CD960((char*)buf, 0, 0);
#else
	new_11910A0((char*)0, 0, 0);
	new_13CD960((char*)0, 0, 0);
#endif

	return ret;
}