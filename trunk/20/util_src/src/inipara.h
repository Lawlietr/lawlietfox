#ifndef _INI_PARA_H_
#  define _INI_PARA_H_

#ifdef INI_EXTERN
#  undef INI_EXTERN
#  define INI_EXTERN
#else
#  define INI_EXTERN extern
#endif

#include <windows.h>

#define   SYS_MALLOC(x)		 HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (x))
#define   SYS_FREE(x)		 HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, (x))

#define	  EXCLUDE_NUM 16					/* 白名单个数(数组最大行数) */
#define   VALUE_LEN 128                     /* 保存值的最大长度 */

#ifdef __cplusplus
extern "C" {
#endif 
INI_EXTERN DWORD WINAPI GetOsVersion(void);
INI_EXTERN LPWSTR stristrW(LPCWSTR Str, LPCWSTR Pat);
INI_EXTERN BOOL WINAPI ini_ready(LPWSTR inifull_name,size_t buf_len);
INI_EXTERN BOOL read_appkey(LPCWSTR lpappname,              /* 区段名 */
				 LPCWSTR lpkey,							    /* 键名  */	
				 LPWSTR  prefstring,						/* 保存值缓冲区 */	
				 size_t bufsize								/* 缓冲区大小 */
				 );
INI_EXTERN int read_appint(LPCWSTR cat, LPCWSTR name);
INI_EXTERN BOOL for_eachSection(LPCWSTR cat, wchar_t (*lpdata)[VALUE_LEN+1], int m);
#ifdef __cplusplus
}
#endif 

#endif   /* end _INI_PARA_H_ */