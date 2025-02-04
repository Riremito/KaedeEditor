#ifndef __AOBSCANNER_H__
#define __AOBSCANNER_H__

#include"Frost.h"
#include"AobScan.h"
#include"Formatter.h"

#define ADDSCANRESULT(tag) result.push_back(Find_##tag##(f));
#define ADDSCANRESULT64(tag) result.push_back(Find_##tag##(f));
#define CheckScanState(var) \
if (!result.back().info.VA) {\
	var = true;\
}


typedef struct {
	std::wstring tag;
	std::wstring patch;
	std::wstring mode;
	AddrInfo info;
} AddrInfoEx;


std::vector<AddrInfoEx> Scanner_Main(Frost &f);
std::vector<AddrInfoEx> Scanner_Main64(Frost &f);

std::vector<AddrInfoEx> Scanner_Client_Edit(Frost &f);

std::vector<AddrInfoEx> Scanner_SelfCrash(Frost &f);
std::vector<AddrInfoEx> Scanner_Themida_VMProtect(Frost &f, int vm_section);
std::vector<AddrInfoEx> Scanner_Themida_VMProtect64(Frost &f, int vm_section64);
std::vector<AddrInfoEx> Scanner_ASProtect(Frost &f, int vm_section);

std::vector<AddrInfoEx> Scanner_Functions_Packet(Frost &f);
std::vector<AddrInfoEx> Scanner_Functions_Packet64(Frost &f);
std::vector<AddrInfoEx> Scanner_Functions_Others(Frost &f);
std::vector<AddrInfoEx> Scanner_Functions_Others64(Frost &f);

std::vector<AddrInfoEx> Scanner_127_0_0_1(Frost &f);

std::vector<AddrInfoEx> TestScan(Frost &f, std::wstring wAob, bool isAll = false);

#endif