#ifndef __AOBSCANNER_H__
#define __AOBSCANNER_H__

#include"Frost.h"


void SetDEVM(bool flag);
bool GetDEVM();

typedef struct {
	std::wstring tag;
	std::wstring patch;
	std::wstring mode;
	AddrInfo info;
} AddrInfoEx;

std::vector<AddrInfoEx> AobScannerMain(Frost &f);
std::vector<AddrInfoEx> VMScanner(Frost &f, int vm_section);
std::vector<AddrInfoEx> StackClearScanner(Frost &f);
std::vector<AddrInfoEx> AobScannerMain64(Frost &f);
std::vector<AddrInfoEx> VMScanner64(Frost &f, int vm_section64);

#endif