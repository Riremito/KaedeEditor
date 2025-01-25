#include"AobScanner.h"


AddrInfoEx Find_Addr_StringPool__ms_aString(Frost &f) {
	AddrInfoEx aix = { L"?ms_aString@StringPool@@0PAPBDA" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"75 ?? 8B ?? ?? ?? ?? ?? 0F BE ?? 6A 04");
	if (res.VA) {
		mode = L"JMS v164.0";
		res = f.GetAddrInfo(*(DWORD *)(res.RA + 0x02 + 0x02));
		return aix;
	}

	res = f.AobScan(L"75 ?? 8B ?? ?? ?? ?? ?? ?? 0F BE ?? 6A 04");
	if (res.VA) {
		mode = L"JMS v188.0";
		res = f.GetAddrInfo(*(DWORD *)(res.RA + 0x02 + 0x03));
		return aix;
	}

	res = f.AobScan(L"0F 85 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? 0F BE ?? 6A 04"); // CMS v86.1
	if (res.VA) {
		mode = L"CMS v86.1";
		res = f.GetAddrInfo(*(DWORD *)(res.RA + 0x06 + 0x03));
		return aix;
	}
	return aix;
}

AddrInfoEx Find_Addr_IWzResMan__GetObjectA(Frost &f) {
	AddrInfoEx aix = { L"?GetObjectA@IWzResMan@@QAE?AVZtl_variant_t@@VZtl_bstr_t@@ABV2@1@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 53 55 56 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 ?? 64 A3 00 00 00 00 8B F1 C7 44 24 ?? 00 00 00 00 8D 44 24 ?? 50 C7 44 24 ?? 00 00 00 00 FF 15");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	return aix;
}


std::vector<AddrInfoEx> Scanner_Functions_Others(Frost &f) {
	std::vector<AddrInfoEx> result;

	ADDSCANRESULT(Addr_StringPool__ms_aString);
	ADDSCANRESULT(Addr_IWzResMan__GetObjectA);
	return result;
}