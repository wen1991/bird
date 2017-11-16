// TLStest.cpp : 定义控制台应用程序的入口点。
//


#include <windows.h>

__declspec(thread) WCHAR g_tlsNum[] = L"test";
void NTAPI t_TlsCallBack_A(PVOID DllHandle, DWORD Reason, PVOID Red)
{
	if (DLL_PROCESS_ATTACH == Reason)
	{
		MessageBox(0, g_tlsNum, L"TLSA", 0);
	}
}

#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK p_thread_callback[] = {
	t_TlsCallBack_A,
	NULL
};
#pragma data_seg()

DWORD WINAPI MyThreadProc(
	_In_ LPVOID lpParameter
)
{
	MessageBox(0, g_tlsNum, L"thread", 0);
	return 0;
}
#if 1
BOOLEAN WINAPI DllMain(IN HINSTANCE hDllHandle,
	IN DWORD     nReason,
	IN LPVOID    Reserved)
#else
int main()
#endif
{
	MessageBox(0, g_tlsNum, L"main", 1);
	CreateThread(NULL, 0, MyThreadProc, NULL, 0, NULL);
	return 0;
}

