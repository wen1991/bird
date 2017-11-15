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
// �ض���PE�õ��ĵ�ַ
void DoRelocation(PVOID NewBase);

//CheckDataValide�������ڼ�黺�����е������Ƿ���Ч��dll�ļ�
//����ֵ�� ��һ����ִ�е�dll�򷵻�TRUE�����򷵻�FALSE��
//lpFileData: ���dll���ݵ��ڴ滺����
//DataLength: dll�ļ��ĳ���
BOOL CheckDataValide(PVOID lpFileData, DWORD DataLength);

//��ʼ��CMemLoadDll������������ӳ��ռ��С
int	InitMemSize(PVOID lpFileData, DWORD DataLength);

//MemLoadLibrary�������ڴ滺���������м���һ��dll����ǰ���̵ĵ�ַ�ռ䣬ȱʡλ��0x10000000
//����ֵ�� �ɹ�����TRUE , ʧ�ܷ���FALSE
//pMemoryAddress:dllӳ���ڴ�
//ImageSize: sizeof(pMemoryAddress)
//lpFileData: ���dll�ļ����ݵĻ�����
//DataLength: �����������ݵ��ܳ���
BOOL LoadLibrary2Mem(PVOID pMemoryAddress, DWORD ImageSize, PVOID lpFileData, DWORD DataLength);

//MemGetProcAddress������dll�л�ȡָ�������ĵ�ַ
//����ֵ�� �ɹ����غ�����ַ , ʧ�ܷ���NULL
//lpProcName: Ҫ���Һ��������ֻ������
FARPROC MemGetProcAddress(LPCSTR lpProcName);

// �ض���PE�õ��ĵ�ַ
void DoRelocation(PVOID NewBase);

//��������ַ��
BOOL FillRavAddress(PVOID pImageBase);

//�������߽�
int GetAlignedSize(DWORD Origin, DWORD Alignment);

//��������dllӳ���ļ��ĳߴ�
int CalcTotalImageSize();

//CopyDllDatas������dll���ݸ��Ƶ�ָ���ڴ����򣬲��������н�
//pSrc: ���dll���ݵ�ԭʼ������
//pDest:Ŀ���ڴ��ַ
void CopyDllDatas(PVOID pDest, PVOID pSrc);

#endif