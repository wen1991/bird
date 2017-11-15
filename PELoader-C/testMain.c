#include<stdlib.h>
#include<Windows.h>
#include<stdio.h>
#include"CLoader.h"


int main()
{

	FILE* TFile = NULL;
	errno_t err;
	WCHAR myDll[] = L"testPE.dll";
	err = _wfopen_s(&TFile, myDll, L"rb");
	if (TFile == NULL)
	{
		printf("[-]i can't open your file!\n");
		exit(-1);
	}
	fseek(TFile, 0, SEEK_END); //定位到文件末 
	DWORD FileLength = ftell(TFile); //文件长度
	fseek(TFile, 0, SEEK_SET); //定位到文件头 

	void *lpBuf = malloc(FileLength);
	fseek(TFile, 0, SEEK_SET); //定位到文件头
	fread(lpBuf, 1, FileLength, TFile);
	int ImageSize = InitMemSize(lpBuf, FileLength);
	PVOID pDllMemory = VirtualAlloc(NULL, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pDllMemory == NULL)
		return FALSE;
	if (!LoadLibrary2Mem(pDllMemory, ImageSize, lpBuf, FileLength)) //加载dll到当前进程的地址空间
		return FALSE;
	typedef DWORD(*DLLFUNCTION)();
	DLLFUNCTION fDll = (DLLFUNCTION)MemGetProcAddress("run");
	if (fDll != NULL)
	{
		fDll();
	}
	else
	{
		DWORD err = GetLastError();
		printf("Error: %d", err);
	}

}