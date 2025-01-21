#include"AobScanner.h"
#include"AobScan.h"
#include"Formatter.h"

bool TestScanAll(Frost &f, std::vector<AddrInfoEx> &result, std::wstring tag, std::wstring mode, std::wstring aob) {
	AddrInfoEx aix = { L"", L"", L"" };
	AddrInfo &res = aix.info;
	aix.tag = tag;
	aix.mode = mode;

	std::vector<AddrInfo> vai = f.AobScanAll(aob);
	if (vai.size() == 0) {
		return false;
	}

	if (2 <= vai.size()) {
		aix.patch = L"ERROR";
	}

	for (auto &v : vai) {
		aix.tag = tag;
		res = v;
		result.push_back(aix);
	}

	return true;
}

std::vector<AddrInfoEx> AobScannerTest(Frost &f) {
	std::vector<AddrInfoEx> result;

	return result;
}