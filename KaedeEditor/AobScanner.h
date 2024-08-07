#ifndef __AOBSCANNER_H__
#define __AOBSCANNER_H__

#include"Frost.h"

typedef struct {
	std::wstring tag;
	std::wstring patch;
	std::wstring mode;
	AddrInfo info;
} AddrInfoEx;

std::vector<AddrInfoEx> AobScannerMain(Frost &f);
std::vector<AddrInfoEx> VMScanner(Frost &f, int vm_section);

#endif