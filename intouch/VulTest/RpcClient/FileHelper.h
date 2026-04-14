#pragma once


#include <windows.h>
#include <iostream>

using namespace std;

class FileHelper {
public:

	static int CheckPathExist(string path);

	static int CheckFileExist(string filename);

	static int fileReader(string filename, char** lpbuf, int* bufsize);
	static int fileWriter(string filename, const char* lpdate, int datesize);
	static int fileWriter(string filename, const char* lpdate, int datesize, int cover);


	static int fileReader_c(string filename, char** lpbuf, int* bufsize);

	static int fileWriter_c(string filename, const char* lpdate, int datesize, int cover);

	static string getReleasePath(const char* path);

};
