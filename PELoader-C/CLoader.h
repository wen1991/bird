#ifndef _CLOADER_H_
#define _CLOADER_H_
#include<Windows.h>
#define CLOADER

#if _DEBUG
	#include<stdio.h>
#endif
typedef   BOOL(__stdcall *ProcDllMain)(HINSTANCE, DWORD, LPVOID);

PVOID pImageBase;
PIMAGE_DOS_HEADER pDosHeader;
PIMAGE_NT_HEADERS pNTHeader;
PIMAGE_SECTION_HEADER pSectionHeader;
ProcDllMain pDllMain;
BOOL isLoadOk;
// 重定向PE用到的地址
void DoRelocation(PVOID NewBase);

//CheckDataValide函数用于检查缓冲区中的数据是否有效的dll文件
//返回值： 是一个可执行的dll则返回TRUE，否则返回FALSE。
//lpFileData: 存放dll数据的内存缓冲区
//DataLength: dll文件的长度
BOOL CheckDataValide(PVOID lpFileData, DWORD DataLength);

//初始化CMemLoadDll，并返回所需映射空间大小
int	InitMemSize(PVOID lpFileData, DWORD DataLength);

//MemLoadLibrary函数从内存缓冲区数据中加载一个dll到当前进程的地址空间，缺省位置0x10000000
//返回值： 成功返回TRUE , 失败返回FALSE
//pMemoryAddress:dll映射内存
//ImageSize: sizeof(pMemoryAddress)
//lpFileData: 存放dll文件数据的缓冲区
//DataLength: 缓冲区中数据的总长度
BOOL LoadLibrary2Mem(PVOID pMemoryAddress, DWORD ImageSize, PVOID lpFileData, DWORD DataLength);

//MemGetProcAddress函数从dll中获取指定函数的地址
//返回值： 成功返回函数地址 , 失败返回NULL
//lpProcName: 要查找函数的名字或者序号
FARPROC MemGetProcAddress(LPCSTR lpProcName);

// 重定向PE用到的地址
void DoRelocation(PVOID NewBase);

//填充引入地址表
BOOL FillRavAddress(PVOID pImageBase);

//计算对齐边界
int GetAlignedSize(DWORD Origin, DWORD Alignment);

//计算整个dll映像文件的尺寸
int CalcTotalImageSize();

//CopyDllDatas函数将dll数据复制到指定内存区域，并对齐所有节
//pSrc: 存放dll数据的原始缓冲区
//pDest:目标内存地址
void CopyDllDatas(PVOID pDest, PVOID pSrc);

#endif