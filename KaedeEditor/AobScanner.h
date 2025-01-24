#ifndef __AOBSCANNER_H__
#define __AOBSCANNER_H__

#include"Frost.h"
#include"AobScan.h"
#include"Formatter.h"

typedef struct {
	std::wstring tag;
	std::wstring patch;
	std::wstring mode;
	AddrInfo info;
} AddrInfoEx;


std::vector<AddrInfoEx> AobScannerMain(Frost &f);
std::vector<AddrInfoEx> AobScannerMain64(Frost &f);

std::vector<AddrInfoEx> Scanner_SelfCrash(Frost &f);
std::vector<AddrInfoEx> Scanner_Themida_VMProtect(Frost &f, int vm_section);
std::vector<AddrInfoEx> Scanner_Themida_VMProtect64(Frost &f, int vm_section64);
std::vector<AddrInfoEx> Scanner_ASProtect(Frost &f, int vm_section);

std::vector<AddrInfoEx> TestScan(Frost &f, std::wstring wAob, bool isAll = false);

#endif