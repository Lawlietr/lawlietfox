#define TETE_BUILD

#include "portable.h"
#include "inipara.h"
#include "safe_ex.h"
#include "ice_error.h"
#include <shlobj.h>
#include <shlwapi.h>
#include <process.h>
#include "mhook-lib/mhook.h"
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _MSC_VER
#  pragma comment(lib, "psapi.lib")
#  pragma comment(lib, "shlwapi.lib")
#endif

HMODULE	dll_module				= NULL;
static  HMODULE	 hShell32		= NULL;
static  wchar_t  appdata_path[VALUE_LEN+1];			/* 自定义的appdata变量路径  */
static  wchar_t  localdata_path[VALUE_LEN+1];

typedef HRESULT (WINAPI *_NtSHGetFolderPath)(HWND hwndOwner,
									    int nFolder,
									    HANDLE hToken,
									    DWORD dwFlags,
									    LPWSTR pszPath);
typedef BOOL (WINAPI *_NtSHGetSpecialFolderPath)(HWND hwndOwner,
									    LPWSTR lpszPath,
									    int csidl,
									    BOOL fCreate);
typedef HRESULT (WINAPI *_NtSHGetSpecialFolderLocation)(HWND hwndOwner,
									    int nFolder,
									    LPITEMIDLIST *ppidl);
typedef HRESULT (WINAPI *_NtSHILCreateFromPath)(PCWSTR pszPath,
									    LPITEMIDLIST *ppidl,
									    DWORD *rgflnOut);

static _NtSHGetFolderPath				TrueSHGetFolderPathW				= NULL;
static _NtSHGetSpecialFolderPath		TrueSHGetSpecialFolderPathW			= NULL;
static _NtSHGetSpecialFolderLocation	TrueSHGetSpecialFolderLocation		= NULL;
static _NtSHILCreateFromPath			TrueSHILCreateFromPath				= NULL;

TETE_EXT_CLASS  
uint32_t GetNonTemporalDataSizeMin_tt( void )
{
	return 0;
}

/* Never used,to be compatible with tete's patch */
TETE_EXT_CLASS 
void * __cdecl memset_nontemporal_tt ( void *dest, int c, size_t count )
{
	return memset(dest, c, count);
}

#ifdef _DEBUG
void __cdecl logmsg(const char * format, ...)
{
	char buffer[MAX_PATH];
	va_list args;
	va_start (args, format);
	vsprintf (buffer,format, args);
	const char *logname = "run_hook.log";
	char dir_str[MAX_PATH/2] = {0}; 
	if ( GetEnvironmentVariableA("APPDATA",dir_str,sizeof(dir_str)-1) > 0 )
	{
		FILE* pFile = NULL;
		strncat(dir_str,"\\",1);
		strncat(dir_str,logname,strlen(logname));
		if ( (pFile = fopen(dir_str,"a+")) != NULL )
		{
			fprintf(pFile,buffer);
			fclose(pFile);
		}
		va_end (args);
	}
	return;
 }
#endif

static DWORD SHNotifyCreateDirectoryW(LPCWSTR path, LPSECURITY_ATTRIBUTES sec)
{
    if (CreateDirectoryW(path, sec))
    {
      SHChangeNotify(SHCNE_MKDIR, SHCNF_PATHW, path, NULL);
      return ERROR_SUCCESS;
    }
    return GetLastError();
}

static BOOL WINAPI NtSHCreateDirectoryExW(LPCWSTR pszPath,SECURITY_ATTRIBUTES *psa)
{
	int ret = ERROR_BAD_PATHNAME;
    if (PathIsRelativeW(pszPath))
    {
		SetLastError(ret);
		return FALSE;
    }
	ret = SHNotifyCreateDirectoryW(pszPath, psa);
    if (ret != ERROR_SUCCESS &&
		ret != ERROR_FILE_EXISTS &&
		ret != ERROR_ALREADY_EXISTS &&
		ret != ERROR_FILENAME_EXCED_RANGE)
    {
        wchar_t *pEnd, *pSlash, szTemp[MAX_PATH + 1];
        lstrcpynW(szTemp, pszPath, MAX_PATH);
        pEnd = PathAddBackslashW(szTemp);
        pSlash = szTemp + 3;
        while (*pSlash)
        {
            while (*pSlash && *pSlash != '\\') pSlash++;
            if (*pSlash)
            {
                *pSlash = 0;

                ret = SHNotifyCreateDirectoryW(szTemp, pSlash + 1 == pEnd ? psa : NULL);
            }
            *pSlash++ = '\\';
        }
    }
    if (ret && (ERROR_CANCELLED != ret))
    {
        ret = ERROR_CANCELLED;
    }
	return ret;
}

unsigned WINAPI init_global_env(void * pParam)
{
	if ( !read_appkey(L"General",L"PortableDataPath",appdata_path,sizeof(appdata_path)) )
	{
		return (0);
	} 
	wstrstr(appdata_path);
	/* 如果ini文件里的appdata设置路径为相对路径 */
	if (appdata_path[1] != L':')
	{
		if ( !PathToCombineW(appdata_path,VALUE_LEN) )
		{
			ZeroMemory(appdata_path,sizeof(appdata_path));
		}
	}
	/* 处理localdata变量 */
	if ( !read_appkey(L"Env",L"TmpDataPath",localdata_path,sizeof(appdata_path)) )
	{
		wcsncpy(localdata_path,appdata_path,VALUE_LEN);
	}
	/* 为appdata建立目录 */
	if ( wcsncat(appdata_path,L"\\AppData",VALUE_LEN) )
	{
		NtSHCreateDirectoryExW(appdata_path,NULL);
	}
	/* 为localdata建立目录 */
	if ( wcsncat(localdata_path,L"\\LocalAppData",VALUE_LEN) )
	{
		NtSHCreateDirectoryExW(localdata_path,NULL);
	}
	return (1);
}

HRESULT WINAPI HookSHGetSpecialFolderLocation(HWND hwndOwner,
											  int nFolder,
											  LPITEMIDLIST *ppidl)								
{  
	if( CSIDL_APPDATA == nFolder		|| 
		CSIDL_COMMON_APPDATA == nFolder || 
		CSIDL_LOCAL_APPDATA == nFolder	||
		(CSIDL_LOCAL_APPDATA|CSIDL_FLAG_CREATE)  == nFolder ||
		(CSIDL_APPDATA|CSIDL_FLAG_CREATE)  == nFolder 
	  )
	{  
		LPITEMIDLIST pidlnew = NULL;
		HRESULT result = 0L;
		if ( !TrueSHILCreateFromPath || appdata_path[0] == L'\0' )
		{
			return TrueSHGetSpecialFolderLocation(hwndOwner, nFolder, ppidl);
		}
		if (CSIDL_LOCAL_APPDATA == nFolder	|| 
			CSIDL_COMMON_APPDATA == nFolder || 
			(CSIDL_LOCAL_APPDATA|CSIDL_FLAG_CREATE)  == nFolder)
		{
			result = TrueSHILCreateFromPath( localdata_path, &pidlnew, NULL);
		}
		else
		{
			result = TrueSHILCreateFromPath(appdata_path, &pidlnew, NULL);
		}
		if (result == S_OK)
		{
			*ppidl = pidlnew;
			return result;
		}
		else
		{
			return TrueSHGetSpecialFolderLocation(hwndOwner, nFolder, ppidl);
		}
	}
	return TrueSHGetSpecialFolderLocation(hwndOwner, nFolder, ppidl);
}

HRESULT WINAPI HookSHGetFolderPathW(HWND hwndOwner,int nFolder,HANDLE hToken,
									DWORD dwFlags,LPWSTR pszPath)								
{  
	if( CSIDL_APPDATA == nFolder		|| 
		CSIDL_COMMON_APPDATA == nFolder || 
		CSIDL_LOCAL_APPDATA == nFolder	||
		(CSIDL_LOCAL_APPDATA|CSIDL_FLAG_CREATE)  == nFolder ||
		(CSIDL_APPDATA|CSIDL_FLAG_CREATE)  == nFolder 
	  )
	{  
		int num = 0;
		if( (CSIDL_APPDATA|CSIDL_FLAG_CREATE)  == nFolder )
		{
			num = _snwprintf(pszPath,MAX_PATH,L"%ls",appdata_path);
		}
		else
		{
			num = _snwprintf(pszPath,MAX_PATH,L"%ls",localdata_path);
		}
		pszPath[num] = L'\0';
		return S_OK;
	}
	else
		return TrueSHGetFolderPathW(hwndOwner, nFolder, hToken,dwFlags,pszPath);
}

BOOL WINAPI HookSHGetSpecialFolderPathW(HWND hwndOwner,LPWSTR lpszPath,
										   int csidl,BOOL fCreate)							
{  
	if (fCreate)
	{
		if( CSIDL_APPDATA == csidl			|| 
			CSIDL_COMMON_APPDATA == csidl	|| 
			CSIDL_LOCAL_APPDATA == csidl	||
			(CSIDL_LOCAL_APPDATA|CSIDL_FLAG_CREATE)  == csidl ||
			(CSIDL_APPDATA|CSIDL_FLAG_CREATE)  == csidl
		   )
		{
			int num = 0;
			if( (CSIDL_APPDATA|CSIDL_FLAG_CREATE)  == csidl )
				num = _snwprintf(lpszPath,MAX_PATH,L"%ls",appdata_path);
			else
				num = _snwprintf(lpszPath,MAX_PATH,L"%ls",localdata_path);
			lpszPath[num] = L'\0';
			return TRUE;
		}
	}
    return TrueSHGetSpecialFolderPathW(hwndOwner,lpszPath,csidl,fCreate);
}


unsigned WINAPI init_portable(void * pParam)
{
	hShell32 = LoadLibraryW(L"shell32.dll");
	if (hShell32 != NULL)
	{
		TrueSHGetFolderPathW = (_NtSHGetFolderPath)GetProcAddress(hShell32,
								"SHGetFolderPathW");
		TrueSHGetSpecialFolderPathW = (_NtSHGetSpecialFolderPath)GetProcAddress(hShell32,
									  "SHGetSpecialFolderPathW");
		TrueSHGetSpecialFolderLocation = (_NtSHGetSpecialFolderLocation)GetProcAddress(hShell32,
									  "SHGetSpecialFolderLocation");
		/* 将会用到SHILCreateFromPath基地址 */
		TrueSHILCreateFromPath = (_NtSHILCreateFromPath)GetProcAddress(hShell32,
									  "SHILCreateFromPath");
	}
	/* hook 下面几个函数 */ 
	if (TrueSHGetSpecialFolderLocation)
	{
		Mhook_SetHook((PVOID*)&TrueSHGetSpecialFolderLocation, (PVOID)HookSHGetSpecialFolderLocation);
	}
#ifdef _DEBUG
	else
	{
		logmsg("TrueSHGetSpecialFolderLocation is null\n");
	}
#endif	
	if (TrueSHGetFolderPathW)
	{
		Mhook_SetHook((PVOID*)&TrueSHGetFolderPathW, (PVOID)HookSHGetFolderPathW);
	}
#ifdef _DEBUG
	else
	{
		logmsg("TrueSHGetFolderPathW is null\n");
	}
#endif
	if (TrueSHGetSpecialFolderPathW)
	{
		Mhook_SetHook((PVOID*)&TrueSHGetSpecialFolderPathW, (PVOID)HookSHGetSpecialFolderPathW);
	}
#ifdef _DEBUG
	else
	{
		logmsg("TrueSHGetSpecialFolderPathW is null\n");
	}
#endif
	return (1);
}

/* uninstall hook */
void WINAPI hook_end(void)
{
	if (TrueSHGetFolderPathW)
	{
		Mhook_Unhook((PVOID*)&TrueSHGetFolderPathW);
	}
	if (TrueSHGetSpecialFolderPathW)
	{
		Mhook_Unhook((PVOID*)&TrueSHGetSpecialFolderPathW);
	}
	if (TrueSHGetSpecialFolderLocation)
	{
		Mhook_Unhook((PVOID*)&TrueSHGetSpecialFolderLocation);
	}
	jmp_end();
	safe_end();
	if (hShell32)
	{
		FreeLibrary(hShell32);
	}
	return;
}

/* This is standard DllMain function. */
#ifdef __cplusplus
extern "C" {
#endif 

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpvReserved)
{
    switch(dwReason) 
	{
		case DLL_PROCESS_ATTACH:
		{
			DisableThreadLibraryCalls(hModule);
			dll_module = (HMODULE)hModule;
			if ( read_appint(L"General",L"SafeEx") )
			{
				init_safed(NULL);
			}
			if ( read_appint(L"General", L"Portable") )
			{
				HANDLE h_thread = (HANDLE)_beginthreadex(NULL,0,&init_global_env,NULL,0,NULL); 
				if (h_thread)
				{
					SetThreadPriority(h_thread,THREAD_PRIORITY_TIME_CRITICAL);
					CloseHandle(h_thread);
				}
				CloseHandle((HANDLE)_beginthreadex(NULL,0,&init_portable,NULL,0,NULL));
			}
			if ( read_appint(L"General",L"CreateCrashDump") )
			{
				CloseHandle((HANDLE)_beginthreadex(NULL,0,&init_exeception,NULL,0,NULL));
			}
			
		}
		break;
		case DLL_PROCESS_DETACH:
			hook_end();
		break;
		case DLL_THREAD_ATTACH:
		break;
		case DLL_THREAD_DETACH:
		break;
		default:
			return FALSE;
	}
	return TRUE;
}

#ifdef __cplusplus
}
#endif 