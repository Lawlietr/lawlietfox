#define SAFE_EXTERN

#include "safe_ex.h"
#include "inipara.h"
#include <shlwapi.h>
#include <psapi.h>
#include "mhook-lib/mhook.h"
#include <tchar.h>
#include <stdio.h>

#define STATUS_ERROR					((NTSTATUS)0x80070000L)
#define NT_SUCCESS(Status)              (((NTSTATUS)(Status)) >= 0)

#ifndef _NTSTATUS_PSDK
#define _NTSTATUS_PSDK
  typedef LONG NTSTATUS;
#endif

#ifndef __UNICODE_STRING_DEFINED
#define __UNICODE_STRING_DEFINED
  typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
  } UNICODE_STRING;
  typedef UNICODE_STRING *PUNICODE_STRING;
#endif

#ifndef __OBJECT_ATTRIBUTES_DEFINED
#define __OBJECT_ATTRIBUTES_DEFINED
  typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
#ifdef _WIN64
    ULONG pad1;
#endif
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
#ifdef _WIN64
    ULONG pad2;
#endif
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
  } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#endif

#ifndef __NT_PROC_THREAD_ATTRIBUTE_ENTRY
#define __NT_PROC_THREAD_ATTRIBUTE_ENTRY
typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY {
    ULONG Attribute;    /* PROC_THREAD_ATTRIBUTE_XXX，参见MSDN中UpdateProcThreadAttribute的说明 */
    SIZE_T Size;        /* Value的大小 */
    ULONG_PTR Value;    /* 保存4字节数据（比如一个Handle）或数据指针 */
    ULONG Unknown;      /* 总是0，可能是用来返回数据给调用者 */
} PROC_THREAD_ATTRIBUTE_ENTRY, *PPROC_THREAD_ATTRIBUTE_ENTRY;
#endif

#ifndef __NT_PROC_THREAD_ATTRIBUTE_LIST
#define __NT_PROC_THREAD_ATTRIBUTE_LIST
typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST {
    ULONG Length;       /* 总的结构大小 */
    PROC_THREAD_ATTRIBUTE_ENTRY Entry[1];
} NT_PROC_THREAD_ATTRIBUTE_LIST;
typedef NT_PROC_THREAD_ATTRIBUTE_LIST *PNT_PROC_THREAD_ATTRIBUTE_LIST;
#endif

#ifndef __CURDIR
#define __CURDIR
typedef struct _CURDIR
{
     UNICODE_STRING DosPath;
     PVOID Handle;
} CURDIR, *PCURDIR;
#endif

#ifndef __STRING
#define __STRING
typedef struct _STRING
{
     WORD Length;
     WORD MaximumLength;
     CHAR * Buffer;
} STRING, *PSTRING;
#endif

#ifndef __RTL_DRIVE_LETTER_CURDIR
#define __RTL_DRIVE_LETTER_CURDIR
typedef struct _RTL_DRIVE_LETTER_CURDIR
{
     WORD Flags;
     WORD Length;
     ULONG TimeStamp;
     STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;
#endif

#ifndef __RTL_USER_PROCESS_PARAMETERS
#define __RTL_USER_PROCESS_PARAMETERS
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
     ULONG MaximumLength;
     ULONG Length;
     ULONG Flags;
     ULONG DebugFlags;
     PVOID ConsoleHandle;
     ULONG ConsoleFlags;
     PVOID StandardInput;
     PVOID StandardOutput;
     PVOID StandardError;
     CURDIR CurrentDirectory;
     UNICODE_STRING DllPath;
     UNICODE_STRING ImagePathName;
     UNICODE_STRING CommandLine;
     PVOID Environment;
     ULONG StartingX;
     ULONG StartingY;
     ULONG CountX;
     ULONG CountY;
     ULONG CountCharsX;
     ULONG CountCharsY;
     ULONG FillAttribute;
     ULONG WindowFlags;
     ULONG ShowWindowFlags;
     UNICODE_STRING WindowTitle;
     UNICODE_STRING DesktopInfo;
     UNICODE_STRING ShellInfo;
     UNICODE_STRING RuntimeData;
     RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
     ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
#endif

extern	HMODULE  dll_module;
static  UINT_PTR m_dwUser32Low;						/* dll 的加载基址 */
static  UINT_PTR m_dwUser32Hi;						/* dll 的加载基址+ImageSize */

typedef HMODULE (WINAPI *_NtLoadLibraryExW)(LPCWSTR lpFileName,
									    HANDLE hFile, 
									    DWORD dwFlags);
typedef NTSTATUS (NTAPI *_NtQueryObject)(HANDLE ObjectHandle,
										ULONG  ObjectInformationClass,
										PVOID  ObjectInformation,
										ULONG  ObjectInformationLength,
										PULONG ReturnLength);
typedef NTSTATUS (NTAPI *_NtQuerySection) (HANDLE SectionHandle, 
										ULONG SectionInformationClass,
										PVOID SectionInformation,
										ULONG SectionInformationLength,
										PULONG ResultLength);
typedef  NTSTATUS (NTAPI *_NtCreateSection)(OUT PHANDLE SectionHandle,
										IN ACCESS_MASK DesiredAccess,
										IN POBJECT_ATTRIBUTES ObjectAttributes,
										IN PLARGE_INTEGER SectionSize OPTIONAL,
										IN ULONG Protect,
										IN ULONG Attributes,
										IN HANDLE FileHandle);
typedef  NTSTATUS (NTAPI *_NtCreateUserProcess)(OUT PHANDLE ProcessHandle,
										OUT PHANDLE ThreadHandle,
										IN ACCESS_MASK ProcessDesiredAccess,
										IN ACCESS_MASK ThreadDesiredAccess,
										IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
										IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
										IN ULONG CreateProcessFlags,
										IN ULONG CreateThreadFlags,
										IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
										IN PVOID Parameter9,
										IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList);
typedef LPVOID (WINAPI *_NtMapViewOfFile)(HANDLE hFileMappingObject,
									    DWORD dwDesiredAccess,
									    DWORD dwFileOffsetHigh, 
									    DWORD dwFileOffsetLow, 
									    SIZE_T dwNumberOfBytesToMap);
typedef HANDLE (WINAPI *_NtCreateFileMapping)(HANDLE hFile, 
									    LPSECURITY_ATTRIBUTES lpAttributes,
									    DWORD flProtect,
                                        DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow,
									    LPCWSTR lpName);
typedef NTSTATUS (NTAPI *_NtTerminateProcess)(HANDLE hProcess,
									    NTSTATUS ExitStatus);

typedef NTSTATUS (NTAPI *_NtCLOSE) ( HANDLE ); 

static _NtCLOSE							TrueNtclose							= NULL;
static _NtCreateFileMapping				TrueCreateFileMapping				= NULL;
static _NtQuerySection					TrueNtQuerySection					= NULL;
static _NtTerminateProcess				TrueNtTerminateProcess				= NULL;
static _NtCreateSection					TrueNtCreateSection					= NULL;
static _NtMapViewOfFile                 TrueMapViewOfFile					= NULL;
static _NtCreateUserProcess             TrueCreateUserProcess				= NULL;
static _NtLoadLibraryExW				TrueLoadLibraryExW					= NULL;

#ifdef _DEBUG
extern void __cdecl logmsg(const char * format, ...);
#endif

BOOL WINAPI GetFileFromObjectName(HANDLE hFile,LPWSTR lpFileName)
{
    HANDLE	hFileMap = NULL;
    DWORD	dwFileSizeHi=0;
	BOOL	ret = FALSE;
	wchar_t pszFilename[MAX_PATH+1];
    DWORD	dwFileSizeLo=GetFileSize(hFile,&dwFileSizeHi);

    if(dwFileSizeLo==0 && dwFileSizeHi==0)
        return ret;
	if (TrueCreateFileMapping)
	{
		hFileMap=TrueCreateFileMapping(hFile,NULL,PAGE_READONLY,0,1,NULL);
	}
    if(hFileMap)
    {
		void *pMem = NULL;
		if (TrueMapViewOfFile)
		{
			pMem = TrueMapViewOfFile(hFileMap,FILE_MAP_READ,0,0,1);
		}
        if(pMem)
        {
            if(GetMappedFileNameW(GetCurrentProcess(),pMem,pszFilename,MAX_PATH))
            {
				UINT DriveStrLen = 0;
				wchar_t dummy[1];
				DriveStrLen = GetLogicalDriveStringsW (0, dummy);
                wchar_t szTemp[DriveStrLen+1];
                if(GetLogicalDriveStringsW(DriveStrLen,szTemp))
                {
                    wchar_t szName[MAX_PATH+1];
                    wchar_t szDrive[3]={0};
                    BOOL bFound = FALSE;
                    wchar_t *p = szTemp;
                    do
                    {
                        wcsncpy(szDrive,p,2);
                        if(QueryDosDeviceW(szDrive,szName,MAX_PATH))
                        {
                            UINT uNameLen = wcslen(szName);
                            if(uNameLen<MAX_PATH)
                            {
                                bFound=wcsnicmp(pszFilename,szName,uNameLen)==0;
                                if(bFound)
                                {
                                    wchar_t szTempFile[MAX_PATH+1];
                                    _snwprintf(szTempFile,MAX_PATH,L"%ls%ls",szDrive,pszFilename+uNameLen);
                                    wcsncpy(pszFilename,szTempFile,MAX_PATH);
                                    wcscpy(lpFileName,pszFilename);
                                    ret = TRUE;
                                }
                            }
                        }
                        while(*p++)
							;
                    } while(!bFound&&*p);
                }
            }
            UnmapViewOfFile(pMem);
        }
        CloseHandle(hFileMap);
    }
    return ret;
}

void WINAPI wstrstr(LPWSTR path)
{
	LPWSTR lp = NULL;
	int post;
	do
	{
		lp =  StrChrW(path,L'/');
		if (lp)
		{
			post = lp-path;
			path[post] = L'\\';
		}
	}
	while (lp!=NULL);
	return;
}

BOOL PathToCombineW(IN LPWSTR lpfile, IN size_t str_len)
{
	BOOL	ret = FALSE;
	wchar_t buf_modname[VALUE_LEN+1] = {0};
	wchar_t tmp_path[MAX_PATH] = {0};
	if ( dll_module && lpfile[1] != L':' )
	{
		wstrstr(lpfile);
		if ( GetModuleFileNameW( dll_module, buf_modname, VALUE_LEN) > 0)
		{
			PathRemoveFileSpecW(buf_modname);
			if ( PathCombineW(tmp_path,buf_modname,lpfile) )
			{
				int n = _snwprintf(lpfile,str_len,L"%ls",tmp_path);
				lpfile[n] = L'\0';
				ret = TRUE;
			}
		}
	}
	return ret;
}

BOOL WINAPI in_whitelist(LPCWSTR lpfile)
{
	wchar_t white_list[EXCLUDE_NUM][VALUE_LEN+1];
	int		i;
	BOOL    ret = FALSE;
	/* iceweasel,plugin-container,plugin-hang-ui进程的路径 */
	GetModuleFileNameW(NULL,white_list[0],VALUE_LEN);
	GetModuleFileNameW(dll_module,white_list[1],VALUE_LEN);
	PathRemoveFileSpecW(white_list[1]);
	PathAppendW(white_list[1],L"plugin-container.exe");
	GetModuleFileNameW(dll_module,white_list[2],VALUE_LEN);
	PathRemoveFileSpecW(white_list[2]);
	PathAppendW(white_list[2],L"plugin-hang-ui.exe");
	if ( for_eachSection(L"whitelist", &white_list[3], EXCLUDE_NUM-3) )
	{
		for ( i=0; i<EXCLUDE_NUM ; i++ )
		{
			if (wcslen(white_list[i]) == 0)
			{
				continue;
			}
			if (white_list[i][1] != L':')
			{
				PathToCombineW(white_list[i],VALUE_LEN);
			}
			if (_wcsnicmp(white_list[i],lpfile,wcslen(lpfile))==0)
			{
				ret = TRUE;
				break;
			}
		}
	}
	return ret;
}

NTSTATUS WINAPI HookNtCreateUserProcess(PHANDLE ProcessHandle,PHANDLE ThreadHandle,
								  ACCESS_MASK ProcessDesiredAccess,ACCESS_MASK ThreadDesiredAccess,
								  POBJECT_ATTRIBUTES ProcessObjectAttributes,
								  POBJECT_ATTRIBUTES ThreadObjectAttributes,
								  ULONG CreateProcessFlags,
								  ULONG CreateThreadFlags,
								  PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
								  PVOID CreateInfo,
								  PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList)
{
	NTSTATUS ret;
	RTL_USER_PROCESS_PARAMETERS mY_ProcessParameters;
	ZeroMemory(&mY_ProcessParameters,sizeof(RTL_USER_PROCESS_PARAMETERS));
	if ( ProcessParameters->ImagePathName.Length > 0 && 
		in_whitelist((LPCWSTR)ProcessParameters->ImagePathName.Buffer) )
	{
	#ifdef _DEBUG
		logmsg("the process %ls in whitelist\n",ProcessParameters->ImagePathName.Buffer);
	#endif
	}
	else
	{
	#ifdef _DEBUG
		logmsg("the process %ls disabled-runes\n",ProcessParameters->ImagePathName.Buffer);
	#endif
		ProcessParameters = &mY_ProcessParameters;
	}
	ret = TrueCreateUserProcess(ProcessHandle, ThreadHandle,
								  ProcessDesiredAccess, ThreadDesiredAccess,
								  ProcessObjectAttributes, ThreadObjectAttributes,
								  CreateProcessFlags, CreateThreadFlags, ProcessParameters,
								  CreateInfo, AttributeList);
	return ret;
}

NTSTATUS WINAPI HookNtCreateSection(PHANDLE SectionHandle,ACCESS_MASK DesiredAccess,
								  POBJECT_ATTRIBUTES pObjectAttributes,PLARGE_INTEGER SectionSize,
								  ULONG Protect,ULONG Attributes,HANDLE FileHandle)
{
	NTSTATUS	Status;
	Status = TrueNtCreateSection(SectionHandle,DesiredAccess,pObjectAttributes,SectionSize,
								 Protect,Attributes,FileHandle);
	if ( NT_SUCCESS(Status)  && FileHandle != NULL )
	{
		if ( DesiredAccess==SECTION_ALL_ACCESS &&
			(Protect & PAGE_EXECUTE) && 
			 Attributes == SEC_IMAGE )
		{
			wchar_t		wFileName[MAX_PATH]={0};
			if (GetFileFromObjectName(FileHandle,wFileName))
			{
				if ( wcslen(wFileName) > 0 && in_whitelist((LPCWSTR)wFileName) )
				{
					;
				}
				else
				{
					TrueNtclose(FileHandle);
					return TrueNtCreateSection(SectionHandle,DesiredAccess,pObjectAttributes,SectionSize,
						   Protect,Attributes,NULL);
				}
				
			}
		}
	}
	return  Status;
}

BOOL WINAPI iSAuthorized(LPCWSTR lpFileName)
{
	BOOL	ret = FALSE;
	LPWSTR	filename = NULL;
	wchar_t *szAuthorizedList[] = {L"comctl32.dll", L"uxtheme.dll", L"indicdll.dll",
								   L"msctf.dll",L"shell32.dll", L"imageres.dll",
								   L"winmm.dll",L"ole32.dll", L"oleacc.dll", 
								   L"oleaut32.dll",L"secur32.dll",L"shlwapi.dll",
								   L"ImSCTip.DLL"
								  };
	WORD line = sizeof(szAuthorizedList)/sizeof(szAuthorizedList[0]);
	if (lpFileName[1] == L':')
	{
		wchar_t sysdir[MAX_PATH];
		if ( (GetEnvironmentVariableW(L"SystemRoot",sysdir,sizeof(sysdir)) > 0) )
		{
			PathAppendW(sysdir,L"system32");
			if ( _wcsnicmp(lpFileName,sysdir,wcslen(sysdir)) == 0 )
			{
				filename = PathFindFileNameW(lpFileName);
			}
		}
	}
	else
	{
		filename = (LPWSTR)lpFileName;
	}
	if (filename)
	{
		WORD  i;
		for(i=0;i<line;i++)
		{
			if ( _wcsicmp(filename,szAuthorizedList[i]) == 0 )
			{
				ret = TRUE;
				break;
			}
		}
	}
	return ret;
}

HMODULE WINAPI HookLoadLibraryExW(LPCWSTR lpFileName,HANDLE hFile,DWORD dwFlags)  
{  
    /* 获取函数的返回地址 */
	UINT_PTR dwCaller;
	wchar_t sysdir[MAX_PATH];
	/* 是否信任的dll */
	if ( iSAuthorized(lpFileName) )
		return TrueLoadLibraryExW(lpFileName, hFile, dwFlags);
	#ifdef __GNUC__
		dwCaller = (UINT_PTR)__builtin_return_address(0);
	#else
		__asm push dword ptr [ebp+4]
		__asm pop  dword ptr [dwCaller]
	#endif
    /* 判断是否是从User32.dll调用 */
    if(dwCaller > m_dwUser32Low && dwCaller < m_dwUser32Hi)  
    {  
	#ifdef _DEBUG
		logmsg("the  %ls disable load\n",lpFileName);
	#endif
        return NULL;  
    } 
    return TrueLoadLibraryExW(lpFileName, hFile, dwFlags);  
}


unsigned WINAPI init_safed(void * pParam)
{
	MODULEINFO	user32ModInfo;
	HMODULE		hNtdll,hKernel32;
	DWORD		ver = GetOsVersion();
	ZeroMemory(&user32ModInfo,sizeof(user32ModInfo));
    if (GetModuleInformation(GetCurrentProcess(), GetModuleHandleA("user32.dll"),   
                         &user32ModInfo, sizeof(user32ModInfo)))
    {
		m_dwUser32Low = (UINT_PTR)user32ModInfo.lpBaseOfDll; 
		m_dwUser32Hi = (UINT_PTR)user32ModInfo.lpBaseOfDll+user32ModInfo.SizeOfImage; 
	}
	hKernel32 = GetModuleHandleW(L"kernel32.dll");
	if (hKernel32)
	{
		TrueLoadLibraryExW = (_NtLoadLibraryExW)GetProcAddress(hKernel32,
							 "LoadLibraryExW");
		TrueCreateFileMapping = (_NtCreateFileMapping)GetProcAddress(hKernel32,
							 "CreateFileMappingW");
		TrueMapViewOfFile = (_NtMapViewOfFile)GetProcAddress(hKernel32,
							 "MapViewOfFile");
	}
	hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (hNtdll)
	{
		TrueNtCreateSection				= (_NtCreateSection)GetProcAddress
										  (hNtdll, "NtCreateSection");
		TrueNtclose						= (_NtCLOSE)GetProcAddress
										  (hNtdll, "NtClose");
	    TrueNtQuerySection				= (_NtQuerySection)GetProcAddress 
										  (hNtdll, "NtQuerySection");
		TrueNtTerminateProcess			= (_NtTerminateProcess)GetProcAddress
										  (hNtdll, "NtTerminateProcess");
		if (ver>502)
		{
			TrueCreateUserProcess       = (_NtCreateUserProcess)GetProcAddress
										  (hNtdll, "NtCreateUserProcess");
		}
	}
	if (TrueLoadLibraryExW)
	{
		Mhook_SetHook((PVOID*)&TrueLoadLibraryExW, (PVOID)HookLoadLibraryExW);
	}
	if (ver>502)
	{
		if (TrueCreateUserProcess)
		{
			Mhook_SetHook((PVOID*)&TrueCreateUserProcess, (PVOID)HookNtCreateUserProcess);
		}
	}
	else
	{
		if (TrueNtCreateSection)
		{
			Mhook_SetHook((PVOID*)&TrueNtCreateSection, (PVOID)HookNtCreateSection);
		}
	}
	return (1);
}

void safe_end(void)
{
	if (TrueNtCreateSection)
	{
		Mhook_Unhook((PVOID*)&TrueNtCreateSection);
	}
	if (TrueCreateUserProcess)
	{
		Mhook_Unhook((PVOID*)&TrueCreateUserProcess);
	}
	return;
}