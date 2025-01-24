#include"AobScanner.h"

std::vector<AddrInfoEx> TestScan(Frost &f, std::wstring wAob, bool isAll) {
	std::vector<AddrInfoEx> result;

	{
		AddrInfoEx aix = { L"TestScan", L"", L"Test" };
		AddrInfo &res = aix.info;

		if (isAll) {
			for (auto &v : f.AobScanAll(wAob)) {
				res = v;
				result.push_back(aix);
				// listview will be broken.
				if (1000 == result.size()) {
					if (MessageBoxW(NULL, L"Stop?", L"TestScan", MB_YESNO) != IDNO) {
						return result;
					}
				}
			}
		}
		else {
			res = f.AobScan(wAob);
			result.push_back(aix);
		}
	}

	return result;
}