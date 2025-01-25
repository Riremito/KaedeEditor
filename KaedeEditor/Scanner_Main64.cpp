#include"AobScanner.h"

// ===== REMOVE CHECKS =====
AddrInfoEx Find_Check_Language_64(Frost &f) {
	AddrInfoEx aix = { L"Check_Language", L"90 E9" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"FF 15 ?? ?? ?? ?? 3D A4 03 00 00 0F 84");
	if (res.VA) {
		res = f.GetAddrInfo(res.VA + 0x0B);
		mode = L"JMS";
		return aix;
	}

	res = f.AobScan(L"FF 15 ?? ?? ?? ?? 3D B6 03 00 00 0F 84");
	if (res.VA) {
		res = f.GetAddrInfo(res.VA + 0x0B);
		mode = L"TWMS";
		return aix;
	}

	res = f.AobScan(L"FF 15 ?? ?? ?? ?? 3D A8 03 00 00 0F 84");
	if (res.VA) {
		res = f.GetAddrInfo(res.VA + 0x0B);
		mode = L"CMS";
		return aix;
	}

	res = f.AobScan(L"FF 15 ?? ?? ?? ?? 3D B5 03 00 00 0F 84");
	if (res.VA) {
		res = f.GetAddrInfo(res.VA + 0x0B);
		mode = L"KMS";
		return aix;
	}

	aix.mode = L"Unknown";
	return aix;
}


// ===== REMOVE NGS =====
AddrInfoEx Find_Addr_NGS_SendWvsSetupStep_64(Frost &f) {
	AddrInfoEx aix = { L"NGS_SendWvsSetupStep" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 54 24 10 89 4C 24 08 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? E9");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}
AddrInfoEx Find_Addr_NGS_HeartBeat_64(Frost &f) {
	AddrInfoEx aix = { L"NGS_HeartBeat", L"48 31 C0 48 FF C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 54 24 10 48 89 4C 24 08 57 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? 48 69 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 ?? E9");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_NGS_Check_1_64(Frost &f) {
	AddrInfoEx aix = { L"NGS_Check_1", L"48 31 C0 48 FF C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 54 24 10 48 89 4C 24 08 B8 ?? ?? 00 00 E8 ?? ?? ?? ?? 48 2B E0 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 ?? ?? ?? ?? ?? ?? ?? BA ?? ?? ?? ?? 48");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_NGS_Check_2_64(Frost &f) {
	AddrInfoEx aix = { L"NGS_Check_2", L"48 31 C0 48 FF C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 54 24 10 48 89 4C 24 08 48 83 EC 48 48 8D 4C 24 28 E8 ?? ?? ?? ?? 90 48");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}


// ===== REMOVE ANTI HACK =====
AddrInfoEx Find_Addr_MSCRC_EnterVM_1_64(Frost &f) {
	AddrInfoEx aix = { L"MSCRC_EnterVM_1", L"jmp MSCRC_LeaveVM_1" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	// short aob test
	res = f.AobScan(L"45 33 C0 BA C9 02 00 00 48 8B 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9");
	if (res.VA) {
		res = f.GetAddrInfo(res.VA + 0x15);
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_MSCRC_LeaveVM_1_64(Frost &f) {
	AddrInfoEx aix = { L"MSCRC_LeaveVM_1" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"88 ?? 88 ?? 88 ?? 48 8B 84 24 ?? ?? ?? ?? 48 05 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8B C8 E8");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_MSCRC_EnterVM_2_64(Frost &f) {
	AddrInfoEx aix = { L"MSCRC_EnterVM_2", L"jmp MSCRC_LeaveVM_2" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	// short aob test
	res = f.AobScan(L"45 33 C0 BA 8C 00 00 00 48 8B 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9");
	if (res.VA) {
		res = f.GetAddrInfo(res.VA + 0x15);
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_MSCRC_LeaveVM_2_64(Frost &f) {
	AddrInfoEx aix = { L"MSCRC_LeaveVM_2" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"88 ?? 88 ?? 88 ?? E8 ?? ?? ?? ?? 0F B6 C0 85 C0 74 ?? E8 ?? ?? ?? ?? 48 8B C8 E8");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_MSCRC_EnterVM_3_64(Frost &f) {
	AddrInfoEx aix = { L"MSCRC_EnterVM_3", L"jmp MSCRC_LeaveVM_3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"33 D2 48 8B 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 D2 48 8B 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9");
	if (res.VA) {
		res = f.GetAddrInfo(res.VA + 0x1E);
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_MSCRC_LeaveVM_3_64(Frost &f) {
	AddrInfoEx aix = { L"MSCRC_LeaveVM_3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"88 ?? 88 ?? 88 ?? 48 8B 84 24 ?? ?? ?? ?? 48 05 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? BA 01 00 00 00");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}


std::vector<AddrInfoEx> Scanner_Main64(Frost &f) {
	std::vector<AddrInfoEx> result;
	// Remove Checks
	ADDSCANRESULT64(Check_Language_64);
	// Remove NGS
	ADDSCANRESULT64(Addr_NGS_SendWvsSetupStep_64);
	ADDSCANRESULT64(Addr_NGS_HeartBeat_64);
	ADDSCANRESULT64(Addr_NGS_Check_1_64);
	ADDSCANRESULT64(Addr_NGS_Check_2_64);
	// Anti Cheat
	ADDSCANRESULT64(Addr_MSCRC_EnterVM_1_64);
	ADDSCANRESULT64(Addr_MSCRC_LeaveVM_1_64);
	ADDSCANRESULT64(Addr_MSCRC_EnterVM_2_64);
	ADDSCANRESULT64(Addr_MSCRC_LeaveVM_2_64);
	ADDSCANRESULT64(Addr_MSCRC_EnterVM_3_64);
	ADDSCANRESULT64(Addr_MSCRC_LeaveVM_3_64);
	return result;
}
