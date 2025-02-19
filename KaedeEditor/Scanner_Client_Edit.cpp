#include"AobScanner.h"
#include"ScannerOption.h"


AddrInfoEx Find_Extra_GMCommand(Frost &f) {
	AddrInfoEx aix = { L"Extra_GMCommand" , L"B8 01 00 00 00 90" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"8A 80 ?? ?? ?? ?? A8 01 0F 84 ?? ?? ?? ?? 8D 45 ?? 50 68 ?? ?? ?? ?? 8D 45 ?? 50 8B CE E8");
		if (res.VA) {
			mode = L"JMS v131.0";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Extra_MapCommand(Frost &f) {
	AddrInfoEx aix = { L"Extra_MapCommand" , L"90 90 90 90 90 90 90 90" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"39 BE ?? ?? ?? ?? 75 12 E8 ?? ?? ?? ?? 2B 86 ?? ?? ?? ?? 3D F4 01 00 00 7D 07 33 C0 E9");
		if (res.VA) {
			mode = L"JMS v131.0";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Extra_GMChat(Frost &f) {
	AddrInfoEx aix = { L"Extra_GMChat" , L"B8 01 00 00 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"E8 ?? ?? ?? ?? 85 C0 74 ?? 6A ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8");
		if (res.VA) {
			mode = L"JMS v194.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"E8 ?? ?? ?? ?? 85 C0 74 ?? 6A ?? 8D 8D 38");
		if (res.VA) {
			mode = L"JMS v186.1";
			return aix;
		}

		res = f.AobScan(L"E8 ?? ?? ?? ?? 85 C0 74 ?? 6A ?? 8D 4D ?? E8 ?? ?? ?? ?? 51 8B CC");
		if (res.VA) {
			mode = L"JMS v164.0";
			return aix;
		}

		res = f.AobScan(L"E8 ?? ?? ?? ?? 85 C0 74 ?? 57 6A ?? 8D 4D ?? E8");
		if (res.VA) {
			mode = L"JMS v131.0";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Extra_GMCommand_Lv1(Frost &f) {
	AddrInfoEx aix = { L"Extra_GMCommand_Lv1" , L"B8 01 00 00 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"E8 ?? ?? ?? ?? 8B 75 ?? A8 01 75 ?? 8B 45 ?? 8B 80 ?? ?? ?? ?? 3B C7 0F 84");
		if (res.VA) {
			mode = L"JMS v194.0";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Extra_GMCommand_Lv2(Frost &f) {
	AddrInfoEx aix = { L"Extra_GMCommand_Lv2" , L"B8 01 00 00 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 4D ?? 51 8D 55 ?? 52 8D 85 ?? ?? ?? ?? 68");
		if (res.VA) {
			mode = L"JMS v194.0";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Extra_GMCommand_Local(Frost &f) {
	AddrInfoEx aix = { L"Extra_GMCommand_Local" , L"B8 01 00 00 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"E8 ?? ?? ?? ?? A8 01 75 ?? 83 BB ?? ?? ?? ?? 00 C7 45 ?? 00 00 00 00 74 ?? C7 45 ?? 01 00 00 00 8D 45 ?? 50 8D 8D ?? ?? ?? ?? 68");
		if (res.VA) {
			mode = L"JMS v194.0";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Extra_MapDropLimit(Frost &f) {
	AddrInfoEx aix = { L"Extra_MapDropLimit" , L"B8 00 00 00 00 90 90 90 90 90 90" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? C1 E8 ?? ?? ?? ?? 45 F0 74");
		if (res.VA) {
			mode = L"JMS v164.0";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Extra_PointItemDropLimit(Frost &f) {
	AddrInfoEx aix = { L"Extra_PointItemDropLimit" , L"EB 2D 90 90 90 90" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"8B 35 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 50 8B CE E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 45 08 8B 48 18 83 C0 18 0B 48 04 0F 85 ?? ?? ?? ?? 8B CF E8");
		if (res.VA) {
			mode = L"JMS v186.1";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Extra_PointItemMultipleDrop(Frost &f) {
	AddrInfoEx aix = { L"Extra_PointItemMultipleDrop" , L"B8 00 00 00 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"E8 ?? ?? ?? ?? 85 C0 59 75 ?? 8B 06 8B CE FF 50");
		if (res.VA) {
			mode = L"JMS v186.1";
			return aix;
		}
	}

	return aix;
}


std::vector<AddrInfoEx> Scanner_Client_Edit(Frost &f) {
	std::vector<AddrInfoEx> result;

	// Chat Fix
	ADDSCANRESULT(Extra_GMCommand);
	ADDSCANRESULT(Extra_MapCommand);
	ADDSCANRESULT(Extra_GMChat);
	ADDSCANRESULT(Extra_GMCommand_Lv1);
	ADDSCANRESULT(Extra_GMCommand_Lv2);
	ADDSCANRESULT(Extra_GMCommand_Local);
	// Drop Fix
	ADDSCANRESULT(Extra_MapDropLimit);
	ADDSCANRESULT(Extra_PointItemDropLimit);
	ADDSCANRESULT(Extra_PointItemMultipleDrop);
	return result;
}