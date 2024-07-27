#ifndef __FORMATTER_H__
#define __FORMATTER_H__
#include<Windows.h>
#include<string>

std::wstring BYTEtoString(BYTE b);
std::wstring WORDtoString(WORD w);
std::wstring DWORDtoString(DWORD dw);
#ifdef _WIN64
std::wstring QWORDtoString(ULONG_PTR u, bool slim=false);
#endif
std::wstring DatatoString(BYTE *b, ULONG_PTR Length, bool space);

#endif