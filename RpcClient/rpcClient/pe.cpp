

#include <Windows.h>
#include "../FileHelper.h"
#pragma comment( lib, "Shlwapi.lib")
#pragma comment(lib,"Dbghelp.lib")

unsigned long long GetSizeOfImage(char* pFileBuff)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuff;
#ifdef _WIN64
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFileBuff + pDos->e_lfanew);
	DWORD dwSizeOfImage = pNt->OptionalHeader.SizeOfImage;
#else
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFileBuff + pDos->e_lfanew);
	DWORD dwSizeOfImage = pNt->OptionalHeader.SizeOfImage;
#endif
	return dwSizeOfImage;
}


ULONGLONG GetImageBase(char* pFileBuff)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFileBuff + pDos->e_lfanew);
	ULONGLONG imagebase = pNt->OptionalHeader.ImageBase;

	return imagebase;
}

//why need to modify imagebase£¿
int SetImageBase(char* chBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);
	pNt->OptionalHeader.ImageBase = (ULONGLONG)chBaseAddress;

	return TRUE;
}








int ImportTable(char* chBaseAddress)
{
	// 	char szGetModuleHandleA[] = { 'G','e','t','M','o','d','u','l','e','H','a','n','d','l','e','A',0 };
	// 	char szGetModuleHandleW[] = { 'G','e','t','M','o','d','u','l','e','H','a','n','d','l','e','W',0 };
	// 	char szInitializeSListHead[] = { 'I','n','i','t','i','a','l','i','z','e','S','L','i','s','t','H','e','a','d',0 };

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((char*)pDos +
		pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (TRUE)
	{
		if (0 == pImportTable->OriginalFirstThunk)
		{
			break;
		}

		char* lpDllName = (char*)((char*)pDos + pImportTable->Name);
		HMODULE hDll = (HMODULE)GetModuleHandleA((LPSTR)lpDllName);
		if (NULL == hDll)
		{
			hDll = LoadLibraryA(lpDllName);
			if (NULL == hDll)
			{
				pImportTable++;
				continue;
			}
		}

		DWORD i = 0;

		PIMAGE_THUNK_DATA lpImportNameArray = (PIMAGE_THUNK_DATA)((char*)pDos + pImportTable->OriginalFirstThunk);

		PIMAGE_THUNK_DATA lpImportFuncAddrArray = (PIMAGE_THUNK_DATA)((char*)pDos + pImportTable->FirstThunk);
		while (TRUE)
		{
			if (0 == lpImportNameArray[i].u1.AddressOfData)
			{
				break;
			}

			FARPROC lpFuncAddress = NULL;

			if (0x80000000 & lpImportNameArray[i].u1.Ordinal)
			{
				lpFuncAddress = (FARPROC)GetProcAddress(hDll, (LPSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF));
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME lpImportByName = (PIMAGE_IMPORT_BY_NAME)((char*)pDos + lpImportNameArray[i].u1.AddressOfData);

				lpFuncAddress = (FARPROC)GetProcAddress(hDll, (LPSTR)lpImportByName->Name);
			}

			if (lpFuncAddress )
			{
				lpImportFuncAddrArray[i].u1.Function = (ULONGLONG)lpFuncAddress;
			}

			i++;
		}

		pImportTable++;
	}

	return TRUE;
}

int RelocationTable(char* chBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);
	PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)(chBaseAddress +
		pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	if ((char*)pLoc == (char*)pDos)
	{
		return TRUE;
	}

	while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0)
	{
		WORD* pLocData = (WORD*)((PBYTE)pLoc + sizeof(IMAGE_BASE_RELOCATION));

		int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		ULONGLONG dwDelta = (ULONGLONG)pDos - pNt->OptionalHeader.ImageBase;

		for (int i = 0; i < nNumberOfReloc; i++)
		{
			if ((pLocData[i] & 0xF000) == 0x3000 || (pLocData[i] & 0xF000) == 0xA000)
				//if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000)
			{
				ULONGLONG* pAddress = (ULONGLONG*)((PBYTE)pDos + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));

				*pAddress += dwDelta;
			}
		}

		pLoc = (PIMAGE_BASE_RELOCATION)((PBYTE)pLoc + pLoc->SizeOfBlock);
	}

	return TRUE;
}

int MapFile(char* pFileBuff, char* chBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFileBuff + pDos->e_lfanew);

	memcpy(chBaseAddress, pFileBuff, pNt->OptionalHeader.SizeOfHeaders);

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	int nNumerOfSections = pNt->FileHeader.NumberOfSections;
	for (int i = 0; i < nNumerOfSections; i++, pSection++)
	{
		if ((0 == pSection->VirtualAddress) || (0 == pSection->SizeOfRawData))
		{
			continue;
		}

		char* chDestMem = (char*)(chBaseAddress + pSection->VirtualAddress);
		char* chSrcMem = (char*)(pFileBuff + pSection->PointerToRawData);

		memcpy(chDestMem, chSrcMem, pSection->SizeOfRawData);
	}

	return TRUE;
}





int LoadPeFile(char* fn, char** pebase) {

	char path[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH, path);

	int ret = 0;
	char* pData = 0;
	int dwFileSize = 0;
	ret = FileHelper::fileReader(fn, &pData, &dwFileSize);
	if (ret <= 0)
	{
		return FALSE;
	}


	char szout[1024];

	unsigned __int64 dwSizeOfImage = GetSizeOfImage(pData);

	ULONGLONG imagebase = GetImageBase(pData);
	if (imagebase <= 0)
	{
		return 0;
	}
	char* chBaseAddress = (char*)VirtualAlloc((char*)imagebase, (DWORD)dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NULL == chBaseAddress)
	{
		delete[] pData;
		return 0;
	}


	ret = MapFile(pData, chBaseAddress);
	//Reloc::recovery((DWORD)chBaseAddress);
	ret = RelocationTable(chBaseAddress);

	//ImportFunTable::recover((DWORD)chBaseAddress);
	ret = ImportTable(chBaseAddress);

	ret = SetImageBase(chBaseAddress);

	*pebase = chBaseAddress;

	return 0;
}
