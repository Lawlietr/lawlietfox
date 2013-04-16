#ifndef _SAFE_EX_H_
#  define _SAFE_EX_H_

#ifdef SAFE_EXTERN
#  undef SAFE_EXTERN
#  define SAFE_EXTERN
#else
#  define SAFE_EXTERN extern
#endif

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif
SAFE_EXTERN void WINAPI wstrstr(LPWSTR path);
SAFE_EXTERN BOOL PathToCombineW(LPWSTR lpfile, size_t str_len);
SAFE_EXTERN unsigned WINAPI init_safed(void * pParam);
SAFE_EXTERN void safe_end(void);
#ifdef __cplusplus
}
#endif 

#endif   /* end _SAFE_EX_H_ */