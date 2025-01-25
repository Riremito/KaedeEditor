#include"AobScanner.h"


std::vector<AddrInfoEx> Scanner_127_0_0_1(Frost &f) {
	std::vector<AddrInfoEx> result;

	AddrInfoEx aix = { L"ServerIP", L"\'127.0.0.1\' 00", L"PServer"};

	// 127.0.0.1
	for (auto &v : f.AobScanAll(L"31 32 37 2E 30 2E 30 2E 31 00", NULL, true)) {
		aix.info = v;
		result.push_back(aix);
	}

	return result;
}