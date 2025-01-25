#include"AobScanner.h"


AddrInfoEx Find_Addr_StringPool__ms_aString_64(Frost &f) {
	AddrInfoEx aix = { L"StringPool::ms_aString" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 81 EC ?? ?? ?? ?? 4? 8? ?? 48 63 C2 48 8D ?? ?? ?? ?? ?? 4? 8? ?? C?");
	if (res.VA) {
		mode = L"JMS v425.2";
		res = f.GetAddrInfo(res.VA + 0x0D + *(signed long int *)(res.RA + 0x0D + 0x03) + 0x07);
		return aix;
	}

	res = f.AobScan(L"48 83 EC ?? 4? 8? ?? 48 63 C2 48 8D ?? ?? ?? ?? ?? 4? 8? ?? C?");
	if (res.VA) {
		mode = L"TWMS v263.3";
		res = f.GetAddrInfo(res.VA + 0x0A + *(signed long int *)(res.RA + 0x0A + 0x03) + 0x07);
		return aix;
	}

	res = f.AobScan(L"75 ?? 4C 8D 25 ?? ?? ?? ?? 49 8B 04 EC 4C 0F BE 38 BA 08 00 00 00 48 8D 0D ?? ?? ?? ?? E8");
	if (res.VA) {
		mode = L"KMS v362.3";
		res = f.GetAddrInfo(res.VA + 0x02 + *(signed long int *)(res.RA + 0x02 + 0x03) + 0x07);
		return aix;
	}

	res = f.AobScan(L"0F 85 ?? ?? ?? ?? 48 8D 2D ?? ?? ?? ?? 4A 8B 44 FD 00 48 0F BE 18 48 89 5C 24 ?? BA 08 00 00 00 48 8D 0D ?? ?? ?? ?? E8");
	if (res.VA) {
		mode = L"JMS v410.2";
		res = f.GetAddrInfo(res.VA + 0x06 + *(signed long int *)(res.RA + 0x06 + 0x03) + 0x07);
		return aix;
	}

	res = f.AobScan(L"0F 85 ?? ?? ?? ?? 4? 8D 2D ?? ?? ?? ?? 4? 8B ?? 2? 48 0F BE 00 48 89 ?? ?? ?? BA 08 00 00 00 48 8D 0D ?? ?? ?? ?? E8");
	if (res.VA) {
		mode = L"JMS v413.1";
		res = f.GetAddrInfo(res.VA + 0x06 + *(signed long int *)(res.RA + 0x06 + 0x03) + 0x07);
		return aix;
	}

	return aix;
}

std::vector<AddrInfoEx> Scanner_Functions_Others64(Frost &f) {
	std::vector<AddrInfoEx> result;

	ADDSCANRESULT64(Addr_StringPool__ms_aString_64);
	return result;
}