
#include <Windows.h>
#include <stdio.h>
#include <shlwapi.h>

int main() {

	DWORD bytesToRead = 0;
	DWORD bytesRead = 0;
	wchar_t fName[] = L"e:\\emerging-pnw\\upwork\\sideload\\copy.bin";
	wchar_t outName[] = L"e:\\emerging-pnw\\upwork\\sideload\\copy.bin.out";
	HANDLE hFile = CreateFile(fName, GENERIC_WRITE| GENERIC_READ, FILE_SHARE_READ , NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}
	DWORD size = 0;
	size = GetFileSize(hFile, 0);
	if (size == 0) {
		printf("Error: Empty file");
	}

	LPVOID fileAlloc = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);

	if (!ReadFile(hFile, fileAlloc, size, &bytesRead, NULL)) {
		return -2;
	}
	CloseHandle(hFile);
	
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileAlloc;

	if (!pDosHeader || pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)  return -1;
		
	PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((BYTE*)pDosHeader + pDosHeader->e_lfanew);

	int sections = ntHeader->OptionalHeader.AddressOfEntryPoint;

	IMAGE_DATA_DIRECTORY import = (IMAGE_DATA_DIRECTORY)ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	unsigned long importRVA = import.VirtualAddress;
	DWORD importSize = import.Size;

	if (importSize == 0) return -4;

	PIMAGE_IMPORT_DESCRIPTOR pImportDescription = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDosHeader + importRVA);

	int counter = 0;
	while (true) {
		IMAGE_IMPORT_DESCRIPTOR pDescription = (IMAGE_IMPORT_DESCRIPTOR)pImportDescription[counter];
		if (pDescription.Name != 0) {
			char* pName = (char*)((BYTE*)pDosHeader + pImportDescription[counter].Name);
			printf("%s\n", pName);

		}
		else break;

		PIMAGE_THUNK_DATA64 pThunkData = (PIMAGE_THUNK_DATA64)((BYTE*)pDosHeader + pDescription.FirstThunk);
		unsigned int counter_2 = 0;
		BYTE* nameRVA = (BYTE*)pThunkData;
		while (true) {
			nameRVA =  (BYTE*)pThunkData + (counter_2* sizeof(PIMAGE_THUNK_DATA64));

			unsigned long* pRVA = (unsigned long*)((BYTE*)pDosHeader + ((PIMAGE_THUNK_DATA64)nameRVA)->u1.AddressOfData);
			if (pRVA == (unsigned long*)pDosHeader) 
				break;

			if ((uintptr_t)pRVA & 0x8000000000000000ULL) {
				printf("0x%p\n", (uintptr_t)pRVA);
				counter_2++;
				continue;
			}

			PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)pRVA;

//			printf("0x%p\n", (uintptr_t)pRVA);
			

			DWORD key = 0xD6AE57C2;		//Key
			char * name = (char *)importByName->Name;

			int length = strlen(name);
			char x = 0;
			bool flag = true;
			for (int i = 0; i < length; i++) {
			
				x = name[i] ^ ((BYTE*)&key)[i % sizeof(key)];
				if (x == 0){
					flag = false;
					name[i] = 0;
					break;
				}
				if (flag) {
					name[i] = x;
				}	
			
			}
			printf("%s\n", name);
			counter_2++;
		}

		counter++;
	}
	
	HANDLE outFile = CreateFileW(outName, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	WriteFile(outFile, pDosHeader, size, &bytesRead, NULL);
	
	CloseHandle(outFile);

	return 0;
}