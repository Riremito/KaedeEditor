#ifndef __SCANNER_OPTIPN_H__
#define __SCANNER_OPTIPN_H__

#include<Windows.h>
#include<string>


enum CompilerIndex {
	CI_ALL = 0,
	CI_VS2006,
	CI_VS2008,
};

const std::wstring CompilerList[] = {
	L"All",
	L"Visual Studio 2006",
	L"Visual Studio 2008+",
};

enum CompilerFlag {
	CF_VS2006 = 0x01,
	CF_VS2008 = 0x02,
	CF_ALL = CF_VS2006 | CF_VS2008,
};

void SetDEVM(bool flag);
bool GetDEVM();
void SetCFlag(CompilerIndex ci);
CompilerFlag GetCFlag();


#endif