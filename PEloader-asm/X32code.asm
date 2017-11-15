.386
.model flat, c
assume fs:nothing 
public myX32code

.data
key db "12345678",0
.code
myX32code proc
			push ebx
			mov ebx, [esp+8]
			mov [ebx], X32loader
			mov eax,code_end
			sub eax, X32loader ;返回值为10
			mov [ebx+4],eax
			pop ebx
			ret
X32loader:	
			call $+5
			pop eax
			sub eax,9
			;mov ebx,[eax-4]													;***********************************
			sub eax,[eax]
			pushad
			push ebp
			mov ebp,esp							
			sub esp,40H							;[EBP-04H] = pImageBase
												;[EBP-08H] = pDosHeader
												;[EBP-0CH] = pNTHeader
												;[EBP-10H] = pSectionHeader
												;[EBP-14H] = pDllMain
												;[EBP-18H] = isLoadOk
												;[EBP-1CH] = lpFileData
												;[EBP-20H] = DataLength
												;[EBP-24H] = ImageSize
												;[EBP-28H] = Kernel32.dll-pImageBase/pDosHeader
												;[EBP-2CH] = VirtualAlloc
												;[EBP-30H] = VirtualProtect
												;[EBP-34H] = GetProcAddress
												;[EBP-38H] = GetModuleHandle
												;[EBP-3CH] = LoadLibrary
												;[EBP-40H] = DllName
			mov [ebp-1CH],eax					;lpFileData=mydll start
			mov [ebp-08H],eax					;pDosHeader=mydll start
			mov [ebp-40H],ebx
			mov eax,[eax+3CH]					;pDosHeader->e_lfanew
			mov ebx,[ebp-1CH]					;pDosHeader
			add eax,ebx							;
			mov [ebp-0CH],eax					;pNTHeader=pDosHeader+pDosHeader->e_lfanew
			mov bx,word ptr[eax+18H]			;enum OPTIONAL_MAGIC Magic
			cmp bx,10BH							;0x10B表明这是一个32位镜像文件。
			jnz myloaderEND
			mov ebx,[eax+50H]					;DWORD SizeOfImage
			mov [ebp-24H],ebx					;ImageSize
			add eax,0F8H						;
			mov [ebp-10H],eax					;pSectionHeader=pNTHeader+sizeof(pNTHeader)
;VirtualAlloc
			MOV	EAX,FS:[30H]					;FS:[30H]指向PEB
			MOV	EAX,[EAX+0CH]					;获取PEB_LDR_DATA结构的指针
			MOV	EAX,[EAX+1CH]					;获取LDR_MODULE链表表首结点的inInitializeOrderModuleList成员的指针  LIST_ENTRY InMemoryOrderModuleList;
			MOV	EAX,[EAX]						;LDR_MODULE链表第二个结点的inInitializeOrderModuleList成员的指针
			MOV	EAX,[EAX+08H]					;inInitializeOrderModuleList偏移8h便得到Kernel32.dll的模块基址
			MOV	EBX,EAX							;Kernel32.dll-pImageBase=hModule
			MOV [EBP-28H],EBX
			MOV	EAX,DWORD PTR [EBX+3CH]			;
			MOV	EAX,DWORD PTR [EBX+EAX+18H+60H+00H]
												;EAX=pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;   EXPORT TABLE

			MOV	ECX,[EBX+EAX+18H]				;DWORD ExportDir.NumberOfNames
			MOV	EAX,[EBX+EAX+20H]  				;DWORD ExportDir.AddressOfNames
			ADD	EAX,EBX							;EAX=pImageBase+AddressOfNames
			PUSH 00007373H						;
			PUSH 65726464H						;
			PUSH 41636F72H						;
			PUSH 50746547H						;"GetProcAddress",0
			MOV  EDX,ESP						;EDX=pName
			PUSH ECX
F1:			
			MOV	EDI,EDX
			POP	ECX
			DEC	ECX
			TEST	ECX,ECX
			JZ	EXIT1
			MOV	ESI,[EAX+ECX*4]					;
			ADD	ESI,EBX
			PUSH	ECX
			MOV	ECX,15							;len("GetProcAddress")
			REPZ	CMPSB						;strcmp(ESI,EDI,ECX)
			TEST	ECX,ECX
			JNZ	F1
	
			POP	ECX
			ADD ESP,10H
			MOV	EAX,DWORD PTR [EBX+3CH]				;
			MOV	EAX,DWORD PTR [EBX+EAX+18H+60H+00H]
			MOV	ESI,[EBX+EAX+24H]					;DWORD ExportDir.AddressOfNameOrdinals
			ADD	ESI,EBX								;pImageBase->ExportDir.AddressOfNameOrdinals
			MOVZX	ESI,WORD PTR[ESI+ECX*2]			;取得进入函数地址表的序号
			MOV	EDI,[EBX+EAX+1CH]					;DWORD ExportDir.AddressOfFunctions
			ADD	EDI,EBX								;pImageBase->ExportDir.AddressOfFunctions
			MOV	EDI,[EDI+ESI*4]						;取得GetProcAddress函数的地址
			ADD	EDI,EBX								;pImageBase+VirtualAddress Of Function				
			MOV [EBP-34H],EDI
				
			PUSH EBX
			PUSH EDI
			PUSH 00000000H
			PUSH 636F6C6CH						 
			PUSH 416C6175H
			PUSH 74726956H
			PUSH ESP							;lpProcName="VirtualAlloc"
			PUSH EBX							;hModule
			CALL EDI							;GetProcAddress(hModule,lpProcName);
			MOV [EBP-2CH],EAX					;EAX=pVirtualAlloc
			ADD ESP,0CH
			POP	EDI
			POP EBX
				
			PUSH EBX
			PUSH EDI
			PUSH 00007463H
			PUSH 65746F72H
			PUSH 506C6175H
			PUSH 74726956H
			PUSH ESP							;lpProcName="VirtualProtect"
			PUSH EBX							;hModule
			CALL EDI							;GetProcAddress(hModule,lpProcName);
			MOV [EBP-30H],EAX
			ADD ESP,0CH
			POP	EDI
			POP EBX

			PUSH EBX
			PUSH EDI
			PUSH 00000000H
			PUSH 41656C64H
			PUSH 6E614865H
			PUSH 6C75646FH
			PUSH 4D746547H
			PUSH ESP							;lpProcName="GetModuleHandleA"
			PUSH EBX							;hModule
			CALL EDI							;GetProcAddress(hModule,lpProcName);
			MOV [EBP-38H],EAX					;GetModuleHandle
			ADD ESP,10H
			POP	EDI
			POP EBX				
				
			PUSH EBX
			PUSH EDI
			PUSH 00000000H
			PUSH 41797261H
			PUSH 7262694CH
			PUSH 64616F4CH
			PUSH ESP							;lpProcName="LoadLibraryA"
			PUSH EBX							;hModule
			CALL EDI							;GetProcAddress(hModule,lpProcName);
			MOV [EBP-3CH],EAX					;LoadLibrary
			ADD ESP,0CH
			POP	EDI
			POP EBX
;VirtualAlloc END
			PUSH 40H							;PAGE_EXECUTE_READWRITE (set easyly)
			PUSH 00003000H						;MEM_COMMIT | MEM_RESERVE
			MOV EAX,[EBP-24H]					;ImageSize
			PUSH EAX
			MOV EAX,[EBP-2CH]
			PUSH 00000000H						;NULL
			CALL EAX							;VirtualAlloc(NULL, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
			MOV [EBP-04H],EAX					;pImageBase
;cpy Headers
			mov eax,[ebp-0CH]					;pNTHeader
			mov eax,[eax+054H]		
			mov ecx,eax			
;MoveSize=pNTHeader->OptionalHeader.SizeOfHeaders
			mov esi,[ebp-1CH]
			mov edi,[EBP-04H]
			cld
			REP MOVSB							;memmove(pImageBase, lpFileData, MoveSize);
				
			;redefine
			mov eax,[EBP-04H]					;pImageBase
			mov [ebp-08H],eax					;pDosHeader
			mov ebx,[eax+3CH]
			add ebx,eax
			mov [ebp-0CH],ebx					;pNTHeader
			XOR ECX,ECX
			mov cx,WORD PTR [ebx+14H]			;WORD SizeOfOptionalHeader
			add ecx,18H							;sizeof(NTHeader)
			add ecx,ebx
			mov [ebp-10H],ecx					;pSectionHeader
			;cpy Sections
			XOR EDX,EDX
			mov dx, word ptr [ebx+06H]			;WORD NumberOfSections
												;eax=pImageBase
												;ecx=pSectionHeader
			mov ebx,ecx							;ebx=pSectionHeader
			test dx,dx
			jz DoRelocation
CopySections:	
			sub dx,1
			mov ecx,[ebx+10H]					;DWORD SizeOfRawData
			test ecx,ecx
			jz 	CopySections
			mov edi,[ebx+0CH]					;DWORD VirtualAddress
			test edi,edi
			jz 	CopySections
			add edi,eax
			mov esi,[ebx+14H]					;DWORD PointerToRawData
			ADD esi,[ebp-1CH]					;lpFileData
			REP MOVSB
			add ebx,28H							;next pSectionHeader
			TEST EDX,EDX
			JNZ CopySections
;CopyDllDatasEnd			
DoRelocation:
			mov eax,[ebp-0CH]					;pNTHeader
			add eax,0A0H						;pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
			mov ecx,[eax+4]						;pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
			test ecx,ecx
			jz	FillRavAddress
			mov ebx,[eax]						;pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
			test ebx,ebx
			jz	FillRavAddress
			mov eax,[ebp-0CH]					;pNTHeader
			mov esi,[ebp-04H]					;pImageBase
			sub esi,[eax+34H]					;Delta=pImageBase-pNTHeader->OptionalHeader.ImageBase
			test esi,esi
			jz FillRavAddress
			add ebx,[ebp-04H]					;ebx=pImageBase + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
												;ebx=(struct BASE_RELOCATION_TABLE )RelocTables
F2:					
			mov eax,[ebx+4]						;SizeOfBlock								
			sub eax,8							;SizeOfBlockDatas
			mov edi,ebx							
			add edi,8							;pBlockDatas
F3:				
			xor edx,edx
			mov dx,word ptr [edi]
			and dx,0F000H
			cmp dx,3000H
			jnz F3
			mov dx,word ptr [edi]
			and dx,0FFFH
			add edx,[ebx]						;DWORD VirtualAddress
			add edx,[ebp-04H]					;pImageBase
			add [edx],esi
			add edi,2
			sub eax,2
			test eax,eax						;NumberOfBlocks
			jnz F3
			mov eax,[ebx+4]
			add ebx,[ebx+4]						;next RelocTable
			sub ecx,eax							;SizeofAll-SizeOfBlock
			TEST ecx,ecx							 
			jnz F2
;DoRelocationEnd
FillRavAddress:
			MOV EAX,[EBP-0CH]					;pNTHeeader
			MOV EAX,[EAX+18H+60H+08H]			;pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
			TEST EAX,EAX			
			JZ FillRavAddressEnd	            ;No Import Table
			ADD EAX,[EBP-04H]					;pImageBase
			PUSH EAX							;pImportDescriptor

F10:		
			MOV EBX,[EAX+0CH]					;Name
			ADD EBX,[EBP-04H]					;pImageBase
			PUSH EBX
			PUSH EBX
			MOV EAX,[EBP-38H]
			CALL EAX							;GetModuleHandle
			POP EBX
			TEST EAX,EAX
			JNZ F5
			PUSH EBX
			MOV EAX,[EBP-3CH]
			CALL EAX							;LoadLibrary
			TEST EAX,EAX
			JZ EXIT2
F5:			
			MOV EDX,EAX							;hdll
			MOV EAX,[ESP]
			MOV ESI,[EBP-04H]
			ADD ESI,[EAX]						;pOriginalIAT
			MOV EDI,[EBP-04H]
			ADD EDI,[EAX+10H]				
F9:			
			MOV EAX,[ESI]				
			TEST EAX,EAX
			JZ F6
			TEST EAX,80000000H	
			JZ F7
			;lpFunction = GetProcAddress(hDll, (LPCSTR)(pOriginalIAT[i].u1.Ordinal & 0x0000FFFF));
			AND EAX,0000FFFFH
			PUSH EDX
			PUSH EAX
			PUSH EDX
			MOV EAX,[EBP-34H]					;[EBP-34H] = GetProcAddress
			CALL EAX
			POP EDX
			JMP F8
F7:			;lpFunction = GetProcAddress(hDll, (char *)pByName->Name);
			ADD EAX,[EBP-04H]
			ADD EAX,2
			PUSH EDX
			PUSH EAX
			PUSH EDX
			MOV EBX,EDX
			MOV EAX,[EBP-34H]
			CALL EAX
			SUB ESP,4
			POP EDX
F8:
			TEST EAX,EAX
			JZ EXIT2
			MOV [EDI],EAX
			ADD EDI,4
			ADD ESI,4
			ADD ECX,1
			JMP F9
F6:			
			MOV EAX,[ESP]
			ADD EAX,14H
			MOV [ESP],EAX
			MOV EBX,[EAX]						;pRealIAT[i].u1.Function = (DWORD)lpFunction;
			TEST EBX,EBX
			JNZ F10
			POP EAX
FillRavAddressEnd:			
			SUB ESP,4							;VirtualProtect
			PUSH ESP
			PUSH 40H
			MOV EAX,[EBP-24H]					;ImageSize
			PUSH EAX
			MOV EAX,[EBP-04H]
			PUSH EAX
			;VirtualProtect(pMemoryAddress, ImageSize, PAGE_EXECUTE_READWRITE, &old);
			MOV EAX,[EBP-30H]					;VirtualProtect
			CALL EAX
			ADD ESP,4
			MOV EAX,[EBP-0CH]
			ADD EAX,34H	
			MOV EBX,[EBP-04H]
			MOV [EAX],EBX						;pNTHeader->OptionalHeader.ImageBase = (DWORD)pMemoryAddress;
			MOV EAX,[EBP-0CH]
			ADD EAX,28H
			MOV EBX,[EBP-04H]
			ADD EBX,[EAX]
			PUSH 0
			PUSH 1			
			MOV EAX,[EBP-04H]
			PUSH EAX
			CALL EBX
			TEST EAX,EAX
			JNZ InitEnd
			push 0
			push 0
			MOV EAX,[EBP-04H]
			PUSH EAX
			CALL EBX
			JMP EXIT2			
InitEnd:		
			MOV EAX,1					;isLoadOk				

EXIT2:		;VirtualFree(pMemoryAddress, 0, MEM_RELEASE);
EXIT1:		
			ADD ESP,40H
myloaderEND:	
			pop ebp
			popad
code_end:	nop
			
myX32code endp
    end