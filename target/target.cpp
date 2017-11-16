// target.cpp: 定义控制台应用程序的入口点。
//
#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include<TlHelp32.h>
char key[] = "12345566787";
void main()
{
	//printf("you should get the key :%s", key);
	//MessageBoxA(NULL, "this is a test", NULL, MB_OK);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	int count = 0;

	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		wprintf(L"创建Toolhelp32Snapshot失败\n");
		return;
	}

	BOOL bMore = Process32First(hProcessSnap, &pe32);
	HANDLE hProcessHandle;

	wprintf(L"%s\t%s\n", L"PName", L"PID");
	wprintf(L"=========================================================\n");
	while (bMore)
	{
		count++;
		wprintf(L"%s\t%d\n", pe32.szExeFile, pe32.th32ProcessID);
		if (wcscmp(pe32.szExeFile, L"EXCEL.EXE") == 0)
		{

			hProcessHandle = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
			TerminateProcess(hProcessHandle, 4);
		}
		bMore = Process32Next(hProcessSnap, &pe32);
	}

	::CloseHandle(hProcessSnap);
	wprintf(L"=========================================================\n");
	wprintf(L"\nCurrent Process count = %d\n", count);
	wprintf(L"\nCurrent PID %d\n", GetCurrentProcessId());
	system("pause");
	return;
}