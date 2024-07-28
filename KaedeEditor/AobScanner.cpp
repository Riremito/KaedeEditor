#include"AobScanner.h"

/*
AddrInfoEx Find_Test(Frost &f) {
	AddrInfoEx aix = { L"Tag"};
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"");
	if (res.VA) {
		mode = L"JMS v186.1";
		return aix;
	}

	return aix;
}
*/

AddrInfoEx Find_StringPool(Frost &f) {
	AddrInfoEx aix = {L"StringPoolArray", L"Patch", L"Mode"};
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"75 ?? 8B ?? ?? ?? ?? ?? 0F BE ?? 6A 04"); // JMS v186.1
	if (res.VA) {
		mode = L"JMS v186.1";
		res = f.GetAddrInfo(*(DWORD *)(res.RA + 0x02 + 0x02));
		return aix;
	}

	res = f.AobScan(L"75 ?? 8B ?? ?? ?? ?? ?? ?? 0F BE ?? 6A 04"); // JMS v194.0
	if (res.VA) {
		mode = L"JMS v194.0";
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

// ===== REMOVE ANTI CHEAT =====
AddrInfoEx Find_HackShield_Init(Frost &f) {
	AddrInfoEx aix = { L"HackShield_Init", L"31 C0 C2 04 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 53 8B D9 83 7B 10 00 0F 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 53 8B D9 8D 4B ?? 89 4D ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0");
	if (res.VA) {
		mode = L"JMS v186.1";
		return aix;
	}

	res = f.AobScan(L"81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 55 ?? 8B ?? 8D ?? ?? 8B CD E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	res = f.AobScan(L"81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 55 56 6A 00 8B F1 E9");
	if (res.VA) {
		mode = L"JMS v332.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_HackShield_EHSvc_Loader_1(Frost &f) {
	AddrInfoEx aix = { L"HackShield_EHSvc_Loader_1", L"31 C0 C2 10 03" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 ?? ?? ?? ?? 33 C0 8D BD ?? ?? ?? ?? F3 AB");
	if (res.VA) {
		mode = L"JMS v186.1";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_HackShield_EHSvc_Loader_2(Frost &f) {
	AddrInfoEx aix = { L"HackShield_EHSvc_Loader_2", L"31 C0 C2 18 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 82 00 00 00 33 C0 8D BD ?? ?? ?? ?? F3 AB C7 45 ?? 00 00 00 00 90 E8 ?? ?? ?? ?? 50 E8");
	if (res.VA) {
		mode = L"JMS v164.0-1";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 82 00 00 00 33 C0 8D BD ?? ?? ?? ?? F3 AB C7 45 ?? 00 00 00 00 E8 ?? ?? ?? ?? 90 50 E8");
	if (res.VA) {
		mode = L"JMS v164.0-2";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 ?? ?? ?? ?? 33 C0 8D BD ?? ?? ?? ?? F3 AB");
	if (res.VA) {
		mode = L"JMS v186.1";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 B9 09 00 00 00 33 C0 8D 7D ?? F3 AB");
	if (res.VA) {
		mode = L"JMS v334.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_HackShield_HeartBeat(Frost &f) {
	AddrInfoEx aix = { L"HackShield_HeatBeat", L"31 C0 C2 04 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 56 BE ?? ?? ?? ?? 56 8D 85 ?? ?? ?? ?? 6A 00 50 E8");
	if (res.VA) {
		mode = L"JMS v186.1";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_HackShield_MKD25tray(Frost &f) {
	AddrInfoEx aix = { L"HackShield_MKD25tray", L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"55 8B EC 83 EC 0C 56 8B F1 83 7E 18 00 0F 85 ?? ?? ?? ?? 83 65 FC 00 8D 45 FC 50 90 E8 ?? ?? ?? ?? 83 7D FC 00 59");
	if (res.VA) {
		mode = L"JMS v164.0-1";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 83 EC 0C 56 8B F1 83 7E 18 00 0F 85 ?? ?? ?? ?? 83 65 FC 00 8D 45 FC 50 E8 ?? ?? ?? ?? 90 83 7D FC 00 59");
	if (res.VA) {
		mode = L"JMS v164-2";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 83 EC 0C 56 8B F1 83 7E 18 00 0F 85 ?? ?? ?? ?? 83 65 FC 00 8D 45 FC 50 FF 15");
	if (res.VA) {
		mode = L"JMS v176.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 83 EC ?? 56 8B F1 57 8D 7E ?? 8B CF E8 ?? ?? ?? ?? 85 C0 0F 85");
	if (res.VA) {
		mode = L"JMS v186.1";
		return aix;
	}

	res = f.AobScan(L"83 EC 0C 56 8B F1 57 8D 7E 30 8B CF E8 ?? ?? ?? ?? 85 C0 0F 85 A1 00 00 00 89 44 24 08 8D 44 24 08 50 FF 15");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	res = f.AobScan(L"83 EC 0C 56 57 6A 00 8B F1 E9");
	if (res.VA) {
		mode = L"JMS v332.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_HackShield_Autoup(Frost &f) {
	AddrInfoEx aix = { L"HackShield_Autoup", L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"56 8B F1 83 7E 14 00 74 16 68 ?? ?? ?? ?? 68 80 00 00 00 90 E8 ?? ?? ?? ?? 83 66 14 00 59 59 5E C3");
	if (res.VA) {
		mode = L"JMS v164.0-1";
		return aix;
	}

	res = f.AobScan(L"56 8B F1 83 7E 14 00 74 16 68 ?? ?? ?? ?? 68 80 00 00 00 E8 ?? ?? ?? ?? 90 83 66 14 00 59 59 5E C3");
	if (res.VA) {
		mode = L"JMS v164.0-2";
		return aix;
	}

	res = f.AobScan(L"56 8B F1 83 7E 14 00 74 ?? 68 ?? ?? ?? ?? 68 80 00 00 00 FF 15");
	if (res.VA) {
		mode = L"JMS v176.0";
		return aix;
	}

	res = f.AobScan(L"56 8D 71 ?? 8B CE E8 ?? ?? ?? ?? 85 C0 74 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15");
	if (res.VA) {
		mode = L"JMS v186.1";
		return aix;
	}

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 0C 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 1C 64 A3 00 00 00 00 8B F1 89 74 24 10 C7 06 ?? ?? ?? ?? 8D 7E 18 8B CF C7 44 24 24 07 00 00 00 E8");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_HackShield_ASPLunchr(Frost &f) {
	AddrInfoEx aix = { L"HackShield_ASPLunchr", L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"55 8B EC 83 EC 0C 56 8B F1 83 7E 14 00 75 ?? 68 ?? ?? ?? ?? 90 E8");
	if (res.VA) {
		mode = L"JMS v164.0-1";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 83 EC 0C 56 8B F1 83 7E 14 00 75 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 90");
	if (res.VA) {
		mode = L"JMS v164.0-2";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 83 EC 0C 56 8B F1 83 7E 14 00 75 ?? 68 ?? ?? ?? ?? FF 15");
	if (res.VA) {
		mode = L"JMS v176.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 83 EC ?? 56 8B F1 57 8D 7E ?? 8B CF E8 ?? ?? ?? ?? 85 C0 75 ?? 68 ?? ?? ?? ?? FF 15");
	if (res.VA) {
		mode = L"JMS v186.1";
		return aix;
	}

	res = f.AobScan(L"83 EC 0C 56 8B F1 57 8D 7E 24 8B CF E8 ?? ?? ?? ?? 85 C0 75 5B 68 ?? ?? ?? ?? FF 15");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	res = f.AobScan(L"83 EC 0C 56 57 6A 00 8B F1 E9");
	if (res.VA) {
		mode = L"JMS v332.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_HackShield_HSUpdate(Frost &f) {
	AddrInfoEx aix = { L"HackShield_HSUpdate", L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 53 8B D9 83 7B 0C 00 56 57 0F 85 ?? ?? ?? ?? 8A 15");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 53 56 8D 59 ?? 57 8B CB E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8A 15");
	if (res.VA) {
		mode = L"JMS v180.1";
		return aix;
	}

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 56 83 C1 ?? 57 89 4D ?? E8 ?? ?? ?? ?? 85 C0 0F 85");
	if (res.VA) {
		mode = L"JMS v186.1";
		return aix;
	}

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 53 56 83 C1 ?? 57 89 4D ?? E8 ?? ?? ?? ?? 85 C0 0F 85");
	if (res.VA) {
		mode = L"JMS v187.0";
		return aix;
	}

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 84 24 ?? ?? ?? ?? 64 A3 00 00 00 00 8D 69 0C 8B CD E8 ?? ?? ?? ?? 85 C0 0F 85");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	return aix;
}
// ===== CLIENT FIX =====
AddrInfoEx Find_WindowMode(Frost &f) {
	AddrInfoEx aix = { L"WindowMode", L"00 00 00 00"};
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"C7 45 E4 10 00 00 00 E8 ?? ?? ?? ?? 8D 45");
	if (res.VA) {
		mode = L"JMS v164.0";
		res = f.GetAddrInfo(res.VA + 0x03);
		return aix;
	}
	res = f.AobScan(L"C7 45 DC 10 00 00 00 6A 03 FF 75 ?? 8D 4D ?? E8");
	if (res.VA) {
		mode = L"JMS v186.1";
		res = f.GetAddrInfo(res.VA + 0x03);
		return aix;
	}
	return aix;
}

AddrInfoEx Find_Ad(Frost &f) {
	AddrInfoEx aix = { L"Ad", L"B8 01 00 00 00 C3"};
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 53 56 57 33 DB 53 FF 15");
	if (res.VA) {
		mode = L"JMS v186.1";
		return aix;
	}

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 64 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 78 64 A3 00 00 00 00 33 FF 57 FF 15");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_MapleNetwork(Frost &f) {
	AddrInfoEx aix = { L"MapleNetwork", L"31 C0 C2 08 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 53 56 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 ?? 64 A3 00 00 00 00 8B F1 8A 5C 24 ?? 8A 44 24 ?? 88 5E ?? 88 46 ?? 80 FB 01 75");
	if (res.VA) {
		mode = L"JMS v194.0";
		return aix;
	}

	return aix;
}

#define ADDSCANRESULT(tag) result.push_back(Find_##tag##(f));
std::vector<AddrInfoEx> AobScannerMain(Frost &f) {
	std::vector<AddrInfoEx> result;

	//result.push_back(Find_StringPool(f));
	ADDSCANRESULT(WindowMode);
	ADDSCANRESULT(Ad);
	ADDSCANRESULT(MapleNetwork);
	ADDSCANRESULT(HackShield_Init);
	ADDSCANRESULT(HackShield_EHSvc_Loader_1);
	ADDSCANRESULT(HackShield_EHSvc_Loader_2);
	ADDSCANRESULT(HackShield_HeartBeat);
	ADDSCANRESULT(HackShield_MKD25tray);
	ADDSCANRESULT(HackShield_Autoup);
	ADDSCANRESULT(HackShield_ASPLunchr);
	ADDSCANRESULT(HackShield_HSUpdate);
	return result;
}