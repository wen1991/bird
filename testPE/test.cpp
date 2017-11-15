#include<Windows.h>
#include<stdio.h>
extern "C" __declspec(dllexport) void run();

#if 0
void main()
{
	char test[256] = { 0 };
	sprintf_s(test,256,"this is my x%dtestdll\n", sizeof(PVOID)*8);
#if _WIN32
	MessageBoxA(NULL, test, "ts", MB_OK);
#elif _WIN64
	MessageBoxA(NULL, test, "ts", MB_OK);
#endif
}
#else
void run()
{
	char test[256] = { 0 };
	sprintf_s(test, 256, "this is my x%dtestdll\n", sizeof(PVOID) * 8);
	MessageBoxA(NULL, test, "ts", MB_OK);

}
BOOLEAN WINAPI DllMain(IN HINSTANCE hDllHandle,
	IN DWORD     nReason,
	IN LPVOID    Reserved)
{
	BOOLEAN bSuccess = TRUE;
	run();
	return bSuccess;

}
#endif
