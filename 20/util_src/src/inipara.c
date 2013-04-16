#define INI_EXTERN

#include "inipara.h"
#include <shlwapi.h>
#include <stdio.h>

extern HMODULE dll_module;

BOOL WINAPI ini_ready(LPWSTR inifull_name,size_t str_len)
{
	BOOL rect = FALSE;
	GetModuleFileNameW(dll_module,inifull_name,str_len);
	PathRemoveFileSpecW(inifull_name);
	PathAppendW(inifull_name,L"portable.ini");
	rect = PathFileExistsW(inifull_name);
	if (!rect)
	{
		if ( PathRemoveFileSpecW(inifull_name) )
		{
			PathAppendW(inifull_name,L"tmemutil.ini");
			rect = PathFileExistsW(inifull_name);
		}
	}
	return rect;
}

BOOL read_appkey(LPCWSTR lpappname,              /* 区段名 */
				 LPCWSTR lpkey,					 /* 键名  */	
				 LPWSTR  prefstring,			 /* 保存值缓冲区 */	
				 size_t  bufsize				 /* 缓冲区大小 */
				 )
{
	DWORD  res = 0;
	LPWSTR lpstring;
	wchar_t inifull_name[MAX_PATH+1];
	if (ini_ready(inifull_name,MAX_PATH))
	{
		lpstring = (LPWSTR)SYS_MALLOC(bufsize);
		res = GetPrivateProfileStringW(lpappname, lpkey ,L"", lpstring, bufsize, inifull_name);
		if (res == 0 && GetLastError() != 0x0)
		{
			SYS_FREE(lpstring);
			printf("this ini config file not found\n");
			return FALSE;
		}
		wcsncpy(prefstring,lpstring,bufsize/sizeof(wchar_t)-1);
		prefstring[res] = '\0';
		SYS_FREE(lpstring);
	}
	return ( res>0 );
}	

int read_appint(LPCWSTR cat,LPCWSTR name)
{
	int res = 0;
	wchar_t inifull_name[MAX_PATH];
	if (ini_ready(inifull_name,MAX_PATH))
	{
		res = GetPrivateProfileIntW(cat, name, 0, inifull_name);
		if(res == 0 && GetLastError() == 0x2)
			printf("this ini config file not found\n");
	}
	return res;
}

BOOL for_eachSection(LPCWSTR cat,						/* ini 区段 */
					 wchar_t (*lpdata)[VALUE_LEN+1],	/* 二维数组首地址,保存多个段值 */
					 int m								/* 二维数组行数 */
					 )
{
	DWORD  res = 0;
	LPWSTR lpstring;
	LPWSTR strKey;
	int  i = 0;
	const wchar_t delim[] = L"=";
	wchar_t inifull_name[MAX_PATH];
	if (ini_ready(inifull_name,MAX_PATH))
	{
		size_t num = VALUE_LEN*sizeof(wchar_t)*m;
		lpstring = (LPWSTR)SYS_MALLOC(num);
		res = GetPrivateProfileSectionW(cat, lpstring, num, inifull_name);
		if (res == 0 && GetLastError() != 0x0)
		{
			SYS_FREE(lpstring);
			printf("this ini config file not found\n");
			return FALSE;
		}
		ZeroMemory(*lpdata,num);
		strKey = lpstring;
		while(*strKey != L'\0'&& i < m) 
		{
			LPWSTR strtmp;
			wchar_t t_str[VALUE_LEN] = {0};
			wcsncpy(t_str,strKey,VALUE_LEN-1);
			strtmp = StrStrW(t_str, delim);
			if (strtmp)
			{
				wcsncpy(lpdata[i],&strtmp[1],VALUE_LEN-1);
			}
			strKey += wcslen(strKey)+1;
			++i;
		}
		SYS_FREE(lpstring);
	}
	return TRUE;
}

LPWSTR stristrW(LPCWSTR Str, LPCWSTR Pat)
{
    wchar_t *pptr, *sptr, *start;

    for (start = (wchar_t *)Str; *start != '\0'; start++)
    {
        for ( ; ((*start!='\0') && (toupper(*start) != toupper(*Pat))); start++);
        if ('\0' == *start) return NULL;
        pptr = (wchar_t *)Pat;
        sptr = (wchar_t *)start;
        while (toupper(*sptr) == toupper(*pptr))
        {
            sptr++;
            pptr++;
            if ('\0' == *pptr) return (start);
        }
    }
    return NULL;
}

DWORD WINAPI GetOsVersion(void)
{
	OSVERSIONINFOEXA	osvi;
	BOOL				bOs = FALSE;
	DWORD				ver = 0L;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXA));
	
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
	if( GetVersionExA((OSVERSIONINFOA*)&osvi) ) 
	{
		if ( VER_PLATFORM_WIN32_NT==osvi.dwPlatformId && 
			osvi.dwMajorVersion > 4 )
		{
			char pszOS[4] = {0};
			_snprintf(pszOS, 3, "%lu%d%lu", osvi.dwMajorVersion,0,osvi.dwMinorVersion);
			ver = strtol(pszOS, NULL, 10);
		}
	}
	return ver;
}