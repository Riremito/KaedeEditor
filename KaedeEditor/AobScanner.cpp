#include"AobScanner.h"
#include"AobScan.h"
#include"Formatter.h"

bool flag_devm = true;
void SetDEVM(bool flag) {
	flag_devm = flag;
}

bool GetDEVM() {
	return flag_devm;
}

// ===== REMOVE CHECKS =====
AddrInfoEx Find_Check_Language(Frost &f) {
	AddrInfoEx aix = { L"Check_Language", L"EB" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"FF 15 ?? ?? ?? ?? 3D A4 03 00 00");
	if (res.VA) {
		mode = L"JMS";
		res = f.GetAddrInfo(res.VA + 0x0B);
		if (*(BYTE *)res.RA == 0x74) {
			aix.patch = L"EB";
			return aix;
		}
		if (*(WORD *)res.RA == 0x840F) {
			aix.patch = L"90 E9";
			return aix;
		}
		res.VA = 0; // ERROR
		return aix;
	}

	res = f.AobScan(L"FF 15 ?? ?? ?? ?? 3D B6 03 00 00");
	if (res.VA) {
		res = f.GetAddrInfo(res.VA + 0x0B);
		mode = L"TWMS";
		if (*(BYTE *)res.RA == 0x74) {
			aix.patch = L"EB";
			return aix;
		}
		if (*(WORD *)res.RA == 0x840F) {
			aix.patch = L"90 E9";
			return aix;
		}
		res.VA = 0; // ERROR
		return aix;
	}

	res = f.AobScan(L"FF 15 ?? ?? ?? ?? 3D A8 03 00 00");
	if (res.VA) {
		res = f.GetAddrInfo(res.VA + 0x0B);
		mode = L"CMS";
		if (*(BYTE *)res.RA == 0x74) {
			aix.patch = L"EB";
			return aix;
		}
		if (*(WORD *)res.RA == 0x840F) {
			aix.patch = L"90 E9";
			return aix;
		}
		res.VA = 0; // ERROR
		return aix;
	}

	res = f.AobScan(L"FF 15 ?? ?? ?? ?? 3D B5 03 00 00");
	if (res.VA) {
		res = f.GetAddrInfo(res.VA + 0x0B);
		mode = L"KMS";
		if (*(BYTE *)res.RA == 0x74) {
			aix.patch = L"EB";
			return aix;
		}
		if (*(WORD *)res.RA == 0x840F) {
			aix.patch = L"90 E9";
			return aix;
		}
		res.VA = 0; // ERROR
		return aix;
	}

	res = f.AobScan(L"FF 15 ?? ?? ?? ?? 3D 6A 03 00 00");
	if (res.VA) {
		res = f.GetAddrInfo(res.VA + 0x0B);
		mode = L"THMS";
		if (*(BYTE *)res.RA == 0x74) {
			aix.patch = L"EB";
			return aix;
		}
		if (*(WORD *)res.RA == 0x840F) {
			aix.patch = L"90 E9";
			return aix;
		}
		res.VA = 0; // ERROR
		return aix;
	}

	aix.mode = L"Unknown";
	return aix;
}

AddrInfoEx Find_Check_Mutex(Frost &f) {
	AddrInfoEx aix = { L"Check_Mutex", L"90 E9" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"FF 15 ?? ?? ?? ?? 3D B7 00 00 00 0F 85");
	if (res.VA) {
		res = f.GetAddrInfo(res.VA + 0x0B);
		mode = L"JMS v164.0";
		return aix;
	}

	return aix;
}

// ===== REMOVE HACKSHIELD =====
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

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 ?? ?? ?? ?? 33 C0 8D BD ?? ?? ?? ?? F3 AB C7 45 FC ?? ?? ?? ?? 68");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_HackShield_EHSvc_Loader_2(Frost &f) {
	AddrInfoEx aix = { L"HackShield_EHSvc_Loader_2", L"31 C0 C2 18 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	/*
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
	*/

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
		mode = L"JMS v164.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_HackShield_MKD25tray(Frost &f) {
	AddrInfoEx aix = { L"HackShield_MKD25tray", L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	/*
	res = f.AobScan(L"55 8B EC 83 EC 0C 56 8B F1 83 7E 18 00 0F 85 ?? ?? ?? ?? 83 65 FC 00 8D 45 FC 50 90 E8 ?? ?? ?? ?? 83 7D FC 00 59");
	if (res.VA) {
		mode = L"JMS v164.0-1";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 83 EC 0C 56 8B F1 83 7E 18 00 0F 85 ?? ?? ?? ?? 83 65 FC 00 8D 45 FC 50 E8 ?? ?? ?? ?? 90 83 7D FC 00 59");
	if (res.VA) {
		mode = L"JMS v164.0-2";
		return aix;
	}
	*/

	res = f.AobScan(L"55 8B EC 83 EC 0C 56 8B F1 83 7E 18 00 0F 85 ?? ?? ?? ?? 83 65 FC 00 8D 45 FC 50 FF 15");
	if (res.VA) {
		mode = L"JMS v164.0";
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

	/*
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
	*/

	res = f.AobScan(L"56 8B F1 83 7E 14 00 74 ?? 68 ?? ?? ?? ?? 68 80 00 00 00 FF 15");
	if (res.VA) {
		mode = L"JMS v164.0";
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

	/*
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
	*/

	res = f.AobScan(L"55 8B EC 83 EC 0C 56 8B F1 83 7E 14 00 75 ?? 68 ?? ?? ?? ?? FF 15");
	if (res.VA) {
		mode = L"JMS v164.0";
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
// ===== REMOVE HACKSHIELD =====
AddrInfoEx Find_HackShield_NullPtr(Frost &f) {
	AddrInfoEx aix = { L"HackShield_NullPtr" , L"31 C9 90" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"8D 48 FC 89 0D ?? ?? ?? ?? EB 06 89 1D ?? ?? ?? ?? C7 06 ?? ?? ?? ?? 89 5C 24 20 89 18 89 5E 08 89 5E 0C 6A 0C");
	if (res.VA) {
		mode = L"JMS v308.0";
		return aix;
	}

	res = f.AobScan(L"8D 48 FC 89 0D ?? ?? ?? ?? EB 06 89 2D ?? ?? ?? ?? C7 06 ?? ?? ?? ?? 89 6C 24 20 89 28 6A 0C");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	res = f.AobScan(L"1B C9 23 CA 57 89 75 F0 89 0D ?? ?? ?? ?? 33 FF 89 7D FC 89 38 57 8D 4E 0C C6 45 FC 01 89 7E 08 E8");
	if (res.VA) {
		aix.patch = L"31 C9";
		mode = L"JMS v180.1";
		return aix;
	}

	return aix;
}

// for vmprotect era
AddrInfoEx Find_HackShield_Packet(Frost &f) {
	AddrInfoEx aix = { L"HackShield_Packet" , L"jmp funcion_restore_code_section" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 56 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 ?? 64 A3 00 00 00 00 8B F1 6A ?? 8D 4C 24 ?? C6 86 ?? ?? ?? ?? 01 E8 ?? ?? ?? ?? 6A 01");
	if (res.VA) {
		mode = L"JMS v322.0";
		return aix;
	}

	return aix;
}

// ===== REMOVE ANTI CHEAT - EASY METHOD =====
AddrInfo Get_Addr_EasyMethod_Ptr(Frost &f, ULONG_PTR uVA, std::wstring preAob, size_t position) {
	AddrInfo res = { 0 };
	AobScan pm(preAob);

	res = f.GetAddrInfo(uVA - pm.size());
	if (!res.VA) {
		return res;
	}

	if (!pm.Compare(res.RA)) {
		return AddrInfo{};
	}

	return f.GetAddrInfo(*(DWORD *)(res.RA + position));
}

ULONG_PTR gEasyMethod_Ptr = 0;
bool Check_EasyMethod(Frost &f, ULONG_PTR uVA) {
	AddrInfo ai = f.GetAddrInfo(uVA + 0x04);

	if (!ai.VA) {
		return false;
	}

	if (*(DWORD *)ai.RA == gEasyMethod_Ptr) {
		return true;
	}

	return false;
}

bool Find_Addr_EasyMethod(Frost &f, std::vector<AddrInfoEx> &result) {
	AddrInfo res = { 0 };

	gEasyMethod_Ptr = 0;

	res = f.AobScan(L"E8 ?? ?? ?? ?? EB 05 E8 ?? ?? ?? ?? 66");
	result.push_back(AddrInfoEx{ L"EasyMethod_Test", L"", L"Easy", res });

	if (!res.VA) {
		return false;
	}

	// start and stop
	result.push_back(AddrInfoEx{ L"EasyMethod_StartKeyCrypt", L"31 C0 C3", L"Easy", f.GetRefAddrRelative(res.VA, 0x01) });
	result.push_back(AddrInfoEx{ L"EasyMethod_StopKeyCrypt", L"31 C0 C3", L"Easy", f.GetRefAddrRelative(res.VA + 0x07, 0x01) });

	// init
	AddrInfoEx aix_ptr = { L"EasyMethod_Ptr" };
	aix_ptr.info = Get_Addr_EasyMethod_Ptr(f, res.VA, L"8B 0D ?? ?? ?? ?? 66 ?? ?? ?? 75 07", 0x02);
	if (aix_ptr.info.VA) {
		aix_ptr.mode = L"JMS v188";
		gEasyMethod_Ptr = aix_ptr.info.VA;
	}

	if (!aix_ptr.info.VA) {
		aix_ptr.info = Get_Addr_EasyMethod_Ptr(f, res.VA, L"8B 0D ?? ?? ?? ?? 75 07", 0x02);
		aix_ptr.mode = L"JMS v186";
		gEasyMethod_Ptr = aix_ptr.info.VA;
	}

	if (!aix_ptr.info.VA) {
		aix_ptr.info = Get_Addr_EasyMethod_Ptr(f, res.VA, L"8B 0D ?? ?? ?? ?? 3B ?? 74 ?? 39 ?? ?? 74 ?? 66 ?? ?? ?? 75 07", 0x02);
		aix_ptr.mode = L"JMS v164";
		gEasyMethod_Ptr = aix_ptr.info.VA;
	}
	result.push_back(aix_ptr);

	AddrInfoEx aix_init = { L"EasyMethod_Init", L"31 C0 C3" , L"Easy" };
	if (!gEasyMethod_Ptr) {
		result.push_back(aix_init);
		return false;
	}

	aix_init.info = f.AobScan(L"33 C0 39 05 ?? ?? ?? ?? 0F 95 C0 C3", Check_EasyMethod);
	result.push_back(aix_init);

	// inlined
	aix_init.tag = L"EasyMethod_Init_inline";
	aix_init.patch = L"90 90 90";
	for (auto &v : f.AobScanAll(L"33 C0 83 3D ?? ?? ?? ?? 00 0F 95 C0 85 C0", Check_EasyMethod)) {
		aix_init.info = f.GetAddrInfo(v.VA + 0x09);
		result.push_back(aix_init);
	}
	return true;
}
AddrInfoEx Find_EasyMethod_Init(Frost &f) {
	AddrInfoEx aix = { L"EasyMethod_Init (CSecurityClient::IsInstantiated)" , L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"E8 ?? ?? ?? ?? 85 C0 74 0A E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 00 0F");
	if (res.VA) {
		res = f.GetRefAddrRelative(res.VA, 0x01);
		mode = L"TWMS v??? - HackShield ver";
		return aix;
	}

	res = f.AobScan(L"83 ?? ?? ?? ?? ?? 00 0F 95 C0 C3 A1 ?? ?? ?? ?? C3 8B 01 8B");
	if (res.VA) {
		mode = L"TWMS v??? - XignCode ver broken";
		return aix;
	}

	/*
	res = f.AobScan(L"33 C0 39 ?? ?? ?? ?? ?? 0F 95 C0 C3 CC CC CC CC C7 01 ?? ?? ?? ?? C3");
	if (res.VA) {
		mode = L"JMS v334.2";
		return aix;
	}

	res = f.AobScan(L"33 C0 39 ?? ?? ?? ?? ?? 0F 95 C0 C3 8B ?? ?? 04 85 C0 74 05 83 ?? 0C EB 02 33 C0");
	if (res.VA) {
		mode = L"TWMS v157.2";
		return aix;
	}

	res = f.AobScan(L"83 ?? ?? ?? ?? ?? 00 0F 95 C0 C3 A1 ?? ?? ?? ?? C3 8B 01 8B");
	if (res.VA) {
		mode = L"TWMS v191";
		return aix;
	}

	res = f.AobScan(L"83 ?? ?? ?? ?? ?? 00 0F 95 C0 C3 8B 44 24 04 85 C0 74 05 83 C0 0C EB 02 33 C0");
	if (res.VA) {
		mode = L"TWMS v192.2";
		return aix;
	}
	*/

	return aix;
}

AddrInfoEx Find_EasyMethod_StartKeyCrypt(Frost &f) {
	AddrInfoEx aix = { L"EasyMethod_StartKeyCrypt", L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"E8 ?? ?? ?? ?? EB 05 E8 ?? ?? ?? ?? 66");
	if (res.VA) {
		res = f.GetRefAddrRelative(res.VA, 0x01);
		mode = L"TWMS v???";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_EasyMethod_StopKeyCrypt(Frost &f) {
	AddrInfoEx aix = { L"EasyMethod_StopKeyCrypt", L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"E8 ?? ?? ?? ?? EB 05 E8 ?? ?? ?? ?? 66");
	if (res.VA) {
		res = f.GetRefAddrRelative(res.VA + 0x07, 0x01);
		mode = L"TWMS v???";
		return aix;
	}

	return aix;
}

// ===== REMOVE ANTI HACK =====
AddrInfoEx Find_DR_Check(Frost &f) {
	AddrInfoEx aix = { L"DR_Check" , L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"55 8B EC 81 EC F0 02 00 00 A1 ?? ?? ?? ?? 33 C5 89 45 FC 53 56 57 6A 00 E9");
	if (res.VA) {
		mode = L"JMS v331.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 FC 53 56 57 E9");
	if (res.VA) {
		mode = L"MSEA v102";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_RemoveMSCRC_Main_RenderFrame(Frost &f) {
	// Remove MSCRC Main - Hook
	AddrInfoEx aix = { L"RemoveMSCRC_Main (IWzGr2D::RenderFrame)" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"56 57 8B F9 8B 07 8B 48 1C 57 FF D1 8B F0 85 F6 7D 0E 68 ?? ?? ?? ?? 57 56 E8 ?? ?? ?? ?? 8B C6 5F 5E C3");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	res = f.AobScan(L"56 57 8B F9 8B 07 8B 48 1C");
	if (res.VA) {
		mode = L"JMS v334";
		return aix;
	}

	res = f.AobScan(L"56 8B F1 8B 06 57 56 FF 50 1C");
	if (res.VA) {
		mode = L"JMS v186.1";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_RemoveMSCRC_Main_Run_LeaveVM(Frost &f) {
	// Remove MSCRC Main - Leave
	AddrInfoEx aix = { L"RemoveMSCRC_Main (CWvsApp::Run LeaveVM)" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"6A 01 FF 15 ?? ?? ?? ?? 8B ?? 08 83 ?? 00 75");
	if (res.VA) {
		mode = L"JMS v186.1";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_RemoveMSCRC_OnEnterField_EnterVM(Frost &f) {
	AddrInfoEx aix = { L"RemoveMSCRC_OnEnterField (CWvsContext::OnEnterField EnterVM)" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"55 8B EC 83 EC 40 53 56 57 89 4D C8 8B 4D C8 E8 ?? ?? ?? ?? E9");
	if (res.VA) {
		res = f.GetAddrInfo(res.VA + 0x14);
		mode = L"JMS v188.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 4D ?? 8B 4D ?? E8 ?? ?? ?? ?? 6A 28 8B 4D ?? E8 ?? ?? ?? ?? E9");
	if (res.VA) {
		res = f.GetAddrInfo(res.VA + 0x3D);
		mode = L"JMS v194.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 6A FF 68 ? ? ? ? ? ? ? ? 64 A1 00 00 00 00 50 81 EC ? ? ? ? ? ? ? ? 53 56 57 A1 ? ? ? ? ? ? ? ? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 8D ? ? ? ? ? ? ? ? C7 45 BC 00 00 00 00 33 C0 89 45 C0 89 45 C4 89 45 C8 89 45 CC 89 45 D0 89 45 D4 C7 45 B0 00 00 00 00 33 C9 89 4D B4 89 4D B8 E8");
	if (res.VA) {
		res = f.GetAddrInfo(res.VA + 0x70);
		mode = L"JMS v334";
		return aix;
	}

	/*
	res = f.AobScan(L"E9 ?? ?? ?? ?? 50 EB 55 2C 8A 4A 9C AF 79 54 A0");
	if (res.VA) {
		mode = L"TWMS v192.2";
		return aix;
	}
	*/

	return aix;
}

AddrInfoEx Find_RemoveMSCRC_OnEnterField_LeaveVM(Frost &f) {
	AddrInfoEx aix = { L"RemoveMSCRC_OnEnterField (CWvsContext::OnEnterField LeaveVM)" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"E8 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 89 45 E8 83 7D E8 00 74");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	res = f.AobScan(L"89 ?? 89 ?? 89 ?? 90 E8 ?? ?? ?? ?? 89 45 ?? E8 ?? ?? ?? ?? 85 C0 74");
	if (res.VA) {
		mode = L"JMS v194.0";
		return aix;
	}

	res = f.AobScan(L"68 FF 00 00 00 6A 00 6A 00 8B 85 ?? ?? ?? ?? 83 C0 68 50 6A 03 FF 15");
	if (res.VA) {
		mode = L"JMS v334";
		return aix;
	}

	/*
	res = f.AobScan(L"8B ?? ?? ?? ?? ?? 81 ?? EC 68 00 00 E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 8B");
	if (res.VA) {
		mode = L"TWMS v192.2";
		return aix;
	}
	*/

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

	res = f.AobScan(L"C7 05 ?? ?? ?? ?? 10 00 00 00 8B 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B");
	if (res.VA) {
		mode = L"THMS v87.0";
		res = f.GetAddrInfo(res.VA + 0x06);
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Launcher(Frost &f) {
	AddrInfoEx aix = { L"Launcher", L"B8 01 00 00 00 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"55 8B EC 83 EC ?? 53 56 57 33 ?? ?? FF 15 ?? ?? ?? ?? 8B ?? ?? 89 ?? ?? ?? ?? ?? 8B");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"83 EC ?? 56 57 33 F6 56 FF 15 ?? ?? ?? ?? 8B 7C 24 ?? 89 3D ?? ?? ?? ?? 8B 87 ?? ?? ?? ?? 6A 65 56");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	res = f.AobScan(L"83 EC ?? 55 56 33 ED 55 FF 15 ?? ?? ?? ?? 8B 74 24 ?? 89 35 ?? ?? ?? ?? 8B 86 ?? ?? ?? ?? 8D 4C 24 ?? 51 C7");
	if (res.VA) {
		mode = L"THMS v88";
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
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 64 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 78 64 A3 00 00 00 00 33 ?? 5? FF 15");
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

AddrInfoEx Find_Extra_GMCommand(Frost &f) {
	AddrInfoEx aix = { L"Extra_GMCommand" , L"B8 01 00 00 00 90" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"8A 80 ?? ?? ?? ?? A8 01 0F 84 ?? ?? ?? ?? 8D 45 ?? 50 68 ?? ?? ?? ?? 8D 45 ?? 50 8B CE E8");
	if (res.VA) {
		mode = L"JMS v131.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Extra_MapCommand(Frost &f) {
	AddrInfoEx aix = { L"Extra_MapCommand" , L"90 90 90 90 90 90 90 90" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"39 BE ?? ?? ?? ?? 75 12 E8 ?? ?? ?? ?? 2B 86 ?? ?? ?? ?? 3D F4 01 00 00 7D 07 33 C0 E9");
	if (res.VA) {
		mode = L"JMS v131.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Extra_GMChat(Frost &f) {
	AddrInfoEx aix = { L"Extra_GMChat" , L"B8 01 00 00 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"E8 ?? ?? ?? ?? 85 C0 74 ?? 6A ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8");
	if (res.VA) {
		mode = L"JMS v194.0";
		return aix;
	}

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

	return aix;
}

AddrInfoEx Find_Extra_GMCommand_Lv1(Frost &f) {
	AddrInfoEx aix = { L"Extra_GMCommand_Lv1" , L"B8 01 00 00 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"E8 ?? ?? ?? ?? 8B 75 ?? A8 01 75 ?? 8B 45 ?? 8B 80 ?? ?? ?? ?? 3B C7 0F 84");
	if (res.VA) {
		mode = L"JMS v194.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Extra_GMCommand_Lv2(Frost &f) {
	AddrInfoEx aix = { L"Extra_GMCommand_Lv2" , L"B8 01 00 00 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 4D ?? 51 8D 55 ?? 52 8D 85 ?? ?? ?? ?? 68");
	if (res.VA) {
		mode = L"JMS v194.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Extra_GMCommand_Local(Frost &f) {
	AddrInfoEx aix = { L"Extra_GMCommand_Local" , L"B8 01 00 00 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"E8 ?? ?? ?? ?? A8 01 75 ?? 83 BB ?? ?? ?? ?? 00 C7 45 ?? 00 00 00 00 74 ?? C7 45 ?? 01 00 00 00 8D 45 ?? 50 8D 8D ?? ?? ?? ?? 68");
	if (res.VA) {
		mode = L"JMS v194.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Extra_MapDropLimit(Frost &f) {
	AddrInfoEx aix = { L"Extra_MapDropLimit" , L"B8 00 00 00 00 90 90 90 90 90 90" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? C1 E8 ?? ?? ?? ?? 45 F0 74");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Extra_PointItemDropLimit(Frost &f) {
	AddrInfoEx aix = { L"Extra_PointItemDropLimit" , L"EB 2D 90 90 90 90" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"8B 35 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 50 8B CE E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 45 08 8B 48 18 83 C0 18 0B 48 04 0F 85 ?? ?? ?? ?? 8B CF E8");
	if (res.VA) {
		mode = L"JMS v186.1";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Extra_PointItemMultipleDrop(Frost &f) {
	AddrInfoEx aix = { L"Extra_PointItemMultipleDrop" , L"B8 00 00 00 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"E8 ?? ?? ?? ?? 85 C0 59 75 ?? 8B 06 8B CE FF 50");
	if (res.VA) {
		mode = L"JMS v186.1";
		return aix;
	}

	return aix;
}

// ===== Addr =====
AddrInfoEx Find_Addr_SendPacket(Frost &f) {
	AddrInfoEx aix = { L"?SendPacket@CClientSocket@@QAEXABVCOutPacket@@@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 10 53 56 8B F1 8D 9E ?? ?? ?? ?? 8B CB 89 5D F0 E8 ?? ?? ?? ?? 8B 46 10 33 C9 3B C1 89 4D FC 0F 84");
	if (res.VA) {
		mode = L"JMS v131.0";
		return aix;
	}

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 10 53 56 8B F1 8D 9E 80 00 00 00 57 8B CB 89 5D F0 E8 ?? ?? ?? ?? 8B 46 0C 33 FF 3B C7");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 ?? 64 A3 00 00 00 00 8B F9 8D 87 ?? ?? ?? ?? 50 8D 4C 24 ?? E8");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 ?? 64 A3 00 00 00 00 89 4D ?? C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 8B 4D ?? 03 48 ?? 89 4D ?? 8B 55 ?? 81 C2 ?? ?? ?? ?? 89 55 ?? 8B 45 ?? 8B 4D ?? 03 48 ?? 89 4D ?? C7 45 ?? 00 00 00 00 E9");
	if (res.VA) {
		mode = L"JMS v308.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 4D E8 A1 ?? ?? ?? ?? 05 ?? ?? ?? ?? 8B 40 1C 05 ?? ?? ?? ?? 89 45 ?? C7 45 ?? 00 00 00 00 E9");
	if (res.VA) {
		mode = L"CMS v99.1";
		return aix;
	}

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 53 56 8B F1 8D 5E ?? 8B CB 89 5D ?? E8 ?? ?? ?? ?? 8B 46 ?? 33 C9 3B C1 89 4D ?? 0F 84");
	if (res.VA) {
		mode = L"KMS v2.55";
		return aix;
	}

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 53 56 8B F1 8D 5E ?? 57 8B CB 89 5D ?? E8 ?? ?? ?? ?? 8B 46 ?? 33 FF 3B C7 89 7D ?? 0F 84");
	if (res.VA) {
		mode = L"KMS v2.84";
		return aix;
	}

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 ?? 64 A3 00 00 00 00 8B F9 8D 47 ?? 50 8D 4C 24 ?? E8");
	if (res.VA) {
		mode = L"KMS v2.114";
		return aix;
	}

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 57 8B F9 8D B7 ?? ?? ?? ?? 8B CE 89 75 ?? E8 ?? ?? ?? ?? 8B 47 08 33 C9 3B C1 89 4D ?? 74");
	if (res.VA) {
		mode = L"THMS v87.0";
		return aix;
	}

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 51 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 ?? 64 A3 00 00 00 00 8B F1 8D 86 ?? ?? ?? ?? 50 8D 4C 24 ?? E8 ?? ?? ?? ?? 8B 46 08 C7 44 24 ?? 00 00 00 00 85 C0 74");
	if (res.VA) {
		mode = L"THMS v88.0";
		return aix;
	}

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 57 8B F9 8D 77 ?? 8B CE 89 75 ?? E8 ?? ?? ?? ?? 8B 47 08 33 C9 3B C1 89 4D ?? 74");
	if (res.VA) {
		mode = L"BMS v24.0";
		return aix;
	}

	return aix;
}

ULONG_PTR gSendPacketAddr = 0;
ULONG_PTR gEnterSendPacketOffset = 0;
bool Check_EnterSendPacket(Frost &f, ULONG_PTR uVA) {
	// get call addr from scan result, and check the call addr
	if (f.GetRefAddrRelative(uVA + gEnterSendPacketOffset, 0x01).VA == gSendPacketAddr) {
		return true;
	}
	return false;
}

AddrInfoEx Find_Addr_EnterSendPacket(Frost &f, ULONG_PTR uSendPacketAddr) {
	AddrInfoEx aix = { L"?SendPacket@@YAXABVCOutPacket@@@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	gSendPacketAddr = uSendPacketAddr;
	gEnterSendPacketOffset = 0x0A;
	res = f.AobScan(L"FF 74 24 04 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C3", Check_EnterSendPacket);
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	gEnterSendPacketOffset = 0x0B;
	res = f.AobScan(L"8B 44 24 04 8B 0D ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? C3", Check_EnterSendPacket);
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_COutPacket(Frost &f) {
	AddrInfoEx aix = { L"??0COutPacket@@QAE@J@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 56 8B F1 83 66 04 00 8D 45 F3 50 8D 4E 04 68 00 01 00 00 89 75 EC E8 ?? ?? ?? ?? FF 75 08 83 65 FC 00 8B CE E8");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 51 56 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 0C 64 A3 00 00 00 00 8B F1 89 74 24 08 68 04 01 00 00 B9 ?? ?? ?? ?? C7 46 04 00 00 00 00 E8");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 51 56 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 ?? 64 A3 00 00 00 00 8B F1 89 74 24 ?? 8D 44 24 1C 50 8D 4E ?? 68 ?? ?? ?? ?? C7 01 00 00 00 00 E8");
	if (res.VA) {
		mode = L"JMS v308.0";
		return aix;
	}

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 51 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 ?? 64 A3 00 00 00 00 8B F1 89 74 24 ?? 33 FF 68 ?? ?? ?? ?? B9 ?? ?? ?? ?? 89 7E 04 E8 ?? ?? ?? ?? 83 C0 04 89 46 04 C7 40 FC 00 01 00 00 8B 44 24 ?? 89 7C 24 ?? 89 3E");
	if (res.VA) {
		mode = L"THMS v88.0";
		return aix;
	}

	// old version
	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 56 8B F1 83 66 04 00 8D 45 F3 50 8D 4E 04 68 00 01 00 00 89 75 EC E8 ?? ?? ?? ?? FF 75 0C 83 65 FC 00 FF 75 08 8B CE E8");
	if (res.VA) {
		mode = L"JMS v131.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_Encode1(Frost &f) {
	AddrInfoEx aix = { L"?Encode1@COutPacket@@QAEXE@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"56 8B F1 6A 01 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 8A 54 24 08 88 14 08 FF 46 08 5E C2 04 00");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"56 8B F1 8B 46 04 57 8D 7E 04 85 C0 74 03 8B 40 FC 8B 4E 08 41 3B C8 76 1E 8B 07 85 C0 74 03 8B 40 FC 03 C0 3B C8 77 FA 8D 4C 24 0C 51 6A 00 50 8B CF E8");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_Encode2(Frost &f) {
	AddrInfoEx aix = { L"?Encode2@COutPacket@@QAEXG@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"56 8B F1 6A 02 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 66 8B 54 24 08 66 89 14 08 83 46 08 02 5E C2 04 00");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"56 8B F1 8B 46 04 57 8D 7E 04 85 C0 74 03 8B 40 FC 8B 4E 08 83 C1 02 3B C8 76 1E 8B 07 85 C0 74 03 8B 40 FC 03 C0 3B C8 77 FA 8D 4C 24 0C 51 6A 00 50 8B CF E8 ?? ?? ?? ?? 8B 56 08 8B 07 66 8B 4C 24 0C 66 89 0C 02 83 46 08 02 5F 5E C2 04 00");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_Encode4(Frost &f) {
	AddrInfoEx aix = { L"?Encode4@COutPacket@@QAEXK@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"56 8B F1 6A 04 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 8B 54 24 08 89 14 08 83 46 08 04 5E C2 04 00");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"56 8B F1 8B 46 04 57 8D 7E 04 85 C0 74 03 8B 40 FC 8B 4E 08 83 C1 04 3B C8 76 1E 8B 07 85 C0 74 03 8B 40 FC 03 C0 3B C8 77 FA 8D 4C 24 0C 51 6A 00 50 8B CF E8 ?? ?? ?? ?? 8B 56 08 8B 07 8B 4C 24 0C 89 0C 02 83 46 08 04 5F 5E C2 04 00");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_EncodeStr(Frost &f) {
	AddrInfoEx aix = { L"?EncodeStr@COutPacket@@QAEXV?$ZXString@D@@@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 8B F1 8B 45 08 83 65 FC 00 85 C0 74 05 8B 40 FC EB 02 33 C0 83 C0 02 50 8B CE E8");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 51 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 10 64 A3 00 00 00 00 8B F1 8B 44 24 20 C7 44 24 18 00 00 00 00 85 C0 74");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_EncodeBuffer(Frost &f) {
	AddrInfoEx aix = { L"?EncodeBuffer@COutPacket@@QAEXPBXI@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"56 57 8B 7C 24 10 8B F1 57 E8 ?? ?? ?? ?? 8B 46 04 03 46 08 57 FF 74 24 10 50 E8 ?? ?? ?? ?? 01 7E 08 83 C4 0C 5F 5E C2 08 00");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"53 56 8B F1 8B 46 04 57 8D 7E 04 85 C0 74 03 8B 40 FC 8B 4E 08 8B 5C 24 14 03 CB 3B C8 76 1E 8B 07 85 C0 74 03 8B 40 FC 03 C0 3B C8 77 FA 8D 54 24 14 52 6A 00 50 8B CF E8 ?? ?? ?? ?? 8B 4E 08 8B 44 24 10 03 0F 53 50 51 E8 ?? ?? ?? ?? 01 5E 08 83 C4 0C 5F 5E 5B C2 08 00");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_ProcessPacket(Frost &f) {
	AddrInfoEx aix = { L"?ProcessPacket@CClientSocket@@IAEXAAVCInPacket@@@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 A1 ?? ?? ?? ?? 56 57 8B F9 8D 4D EC 89 45 F0 E8 ?? ?? ?? ?? 8B 75 08 83 65 FC 00 8B CE E8 ?? ?? ?? ?? 0F B7 C0 8D 48 F7 83 F9 07 77");
	if (res.VA) {
		mode = L"JMS v131.0";
		return aix;
	}

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 A1 ?? ?? ?? ?? 56 57 8B F9 8D 4D EC 89 45 F0 E8 ?? ?? ?? ?? 8B 75 08 83 65 FC 00 8B CE E8 ?? ?? ?? ?? 0F B7");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 08 53 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 18 64 A3 00 00 00 00 8B F9 8B 1D ?? ?? ?? ?? 89 5C 24 14 85 DB 74");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 1C 64 A3 00 00 00 00 8B D9 8B 2D ?? ?? ?? ?? 89 6C 24 ?? 85 ED 74");
	if (res.VA) {
		mode = L"CMS v104.1";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_Decode1(Frost &f) {
	AddrInfoEx aix = { L"?Decode1@CInPacket@@QAEEXZ" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 0F B7 51 0C 8B 41 08 83 65 FC 00 53 56 8B 71 14 2B D6 57 03 C6 83 FA 01");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 14 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 65 F0 89 4D E8 0F B7 41 0C 8B 51 14 8B 71 08 2B C2 C7 45 FC 00 00 00 00 83 F8 01");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 51 8B 51 ?? 8B 41 ?? 56 0F B7 71 ?? 2B F2 03 C2 83 FE 01 5E 73 ?? 68");
	if (res.VA) {
		mode = L"THMS v87.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_Decode2(Frost &f) {
	AddrInfoEx aix = { L"?Decode2@CInPacket@@QAEGXZ" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 0F B7 51 0C 8B 41 08 83 65 FC 00 53 56 8B 71 14 2B D6 57 03 C6 83 FA 02");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 14 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 65 F0 89 4D E8 0F B7 41 0C 8B 51 14 8B 71 08 2B C2 C7 45 FC 00 00 00 00 83 F8 02");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 51 8B 51 14 8B 41 08 56 0F B7 71 0C 2B F2 03 C2 83 FE 02 5E 73 ?? 68");
	if (res.VA) {
		mode = L"BMS v24.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_Decode4(Frost &f) {
	AddrInfoEx aix = { L"?Decode4@CInPacket@@QAEKXZ" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 0F B7 51 0C 8B 41 08 83 65 FC 00 53 56 8B 71 14 2B D6 57 03 C6 83 FA 04");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 14 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 65 F0 89 4D E8 0F B7 41 0C 8B 51 14 8B 71 08 2B C2 C7 45 FC 00 00 00 00 83 F8 04");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 51 8B 51 14 8B 41 08 56 0F B7 71 0C 2B F2 03 C2 83 FE 04 5E 73 ?? 68");
	if (res.VA) {
		mode = L"BMS v24.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_DecodeStr(Frost &f) {
	AddrInfoEx aix = { L"?DecodeStr@CInPacket@@QAE?AV?$ZXString@D@@XZ" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 18 53 56 57 89 65 F0 6A 01 33 FF 8B F1 5B");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 14 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 65 F0 8B F1 89 75 E8 C7 45 EC 00 00 00 00 8B 7D 08 B8 01 00 00 00 89 45 FC C7 07 00 00 00 00 0F B7 56 0C 8B 4E 08 89 45 EC 8B 46 14 2B D0 52 03 C1 50 57 E8");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 83 65 ?? 00 83 65 ?? 00 56 57 8B F1 8B 46 14 0F B7 4E 0C 6A 01");
	if (res.VA) {
		mode = L"BMS v24.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_DecodeBuffer(Frost &f) {
	AddrInfoEx aix = { L"?DecodeBuffer@CInPacket@@QAEXPAXI@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 83 65 FC 00 53 56 8B F1 0F B7 46 0C");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 14 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 65 F0 8B F1 89 75 E8 0F B7 46 0C 8B 4E 14 8B 56 08 8B 7D 0C 2B C1 03 CA C7 45 FC 00 00 00 00 3B C7 73");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 56 8B F1 0F B7 56 0C 8B 4E 14 8B 46 08 57 8B 7D 0C 2B D1 03 C1 3B D7 73 ?? 68");
	if (res.VA) {
		mode = L"BMS v24.0";
		return aix;
	}

	return aix;
}

// Addr just ref
AddrInfoEx Find_Addr_StringPool__ms_aString(Frost &f) {
	AddrInfoEx aix = { L"?ms_aString@StringPool@@0PAPBDA"};
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

// ===== String =====
std::wstring StrPatchPadding(AddrInfo &res, std::wstring str) {
	std::wstring patch = L"\'" + str + L"\' 00";
	size_t str_len = str.length();
	size_t target_len = strlen((char *)res.RA);
	for(size_t i= str_len; i< target_len; i++){
		patch += L" 00";
	}
	return patch;
}
bool Find_String_IPs(Frost &f, std::vector<AddrInfoEx> &result) {
	AddrInfoEx aix = { L"ServerIP" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;
	bool check = false;
	// JMS
	res = f.ScanString("61.215.216.38");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"JMS v29";
		result.push_back(aix);
		check &= true;
	}

	res = f.ScanString("59.128.93.105");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"JMS v164.0";
		result.push_back(aix);
		check &= true;
	}

	res = f.ScanString("111.87.33.105");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"JMS v302.0";
		result.push_back(aix);
		check &= true;
	}

	if (check) {
		return true;
	}

	// TWMS
	res = f.ScanString("tw.login.maplestory.gamania.com");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"TWMS v157";
		result.push_back(aix);
		check &= true;
	}

	if (check) {
		return true;
	}

	// CMS
	res = f.ScanString("mxdlogin.poptang.com");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"CMS v86.1";
		result.push_back(aix);
		check = true;
		// more
		res = f.ScanString("mxdlogin2.poptang.com");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"CMS v86.1";
			result.push_back(aix);
		}

		res = f.ScanString("mxdlogin3.poptang.com");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"CMS v86.1";
			result.push_back(aix);
		}

		res = f.ScanString("mxdlogin5.poptang.com");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"CMS v86.1";
			result.push_back(aix);
		}

		res = f.ScanString("mxdlogin6.poptang.com");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"CMS v86.1";
			result.push_back(aix);
		}
	}

	if (check) {
		return true;
	}

	// KMS
	res = f.ScanString("220.90.204.10");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"KMS v2.109";
		result.push_back(aix);
		check = true;
		// more
		res = f.ScanString("220.90.204.11");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
			check = true;
		}
		res = f.ScanString("220.90.204.12");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
			check = true;
		}
		res = f.ScanString("220.90.204.13");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
			check = true;
		}
		res = f.ScanString("220.90.204.14");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
			check = true;
		}
		res = f.ScanString("220.90.204.15");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
			check = true;
		}
		res = f.ScanString("220.90.204.16");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
			check = true;
		}
		res = f.ScanString("220.90.204.17");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
			check = true;
		}
		res = f.ScanString("220.90.204.18");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
			check = true;
		}
		res = f.ScanString("220.90.204.19");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
			check = true;
		}
		res = f.ScanString("220.90.204.20");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
			check = true;
		}
	}

	if (check) {
		return true;
	}

	// MSEA
	res = f.ScanString("203.116.196.8");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"MSEA v100";
		result.push_back(aix);
		check &= true;
	}

	res = f.ScanString("203.188.239.82");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"MSEA v100";
		result.push_back(aix);
		check &= true;
	}

	if (check) {
		return true;
	}

	// KMST
	/*
	res = f.ScanString("175.207.2.136");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"KMST v2.497";
		result.push_back(aix);
		check &= true;
	}

	if (check) {
		return true;
	}
	*/

	// BMS
	res = f.ScanString("200.229.55.4");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"BMS v24";
		result.push_back(aix);
		check &= true;
	}

	if (check) {
		return true;
	}

	// THMS
	res = f.ScanString("61.90.227.132");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"THMS v88";
		result.push_back(aix);
		check &= true;
	}

	if (check) {
		return true;
	}

	return false;
}

// Main

#define ADDSCANRESULT(tag) result.push_back(Find_##tag##(f));
std::vector<AddrInfoEx> AobScannerMain(Frost &f) {
	std::vector<AddrInfoEx> result;
	bool vmprotect = false;
	// String
	Find_String_IPs(f, result);
	// Remove Checks
	ADDSCANRESULT(Check_Language);
	ADDSCANRESULT(Check_Mutex);
	// Remove HackShield 2024 ver by Riremito
	ADDSCANRESULT(HackShield_NullPtr);
	ADDSCANRESULT(HackShield_Packet);
	if (result.back().info.VA) {
		vmprotect = true;
	}
	//if (!result.back().info.VA) {
		// Remove HackShield by Riremito, written for JMS/EMS and also works for KMS
		ADDSCANRESULT(HackShield_Init);
		ADDSCANRESULT(HackShield_EHSvc_Loader_1);
		ADDSCANRESULT(HackShield_EHSvc_Loader_2);
		ADDSCANRESULT(HackShield_HeartBeat);
		ADDSCANRESULT(HackShield_MKD25tray);
		ADDSCANRESULT(HackShield_Autoup);
		ADDSCANRESULT(HackShield_ASPLunchr);
		ADDSCANRESULT(HackShield_HSUpdate);
	//}
	// Remove HackShield/XignCode/BlackCipher by chuichui, written for TWMS and others

	Find_Addr_EasyMethod(f, result);
	//ADDSCANRESULT(EasyMethod_StartKeyCrypt);
	//ADDSCANRESULT(EasyMethod_StopKeyCrypt);
	//ADDSCANRESULT(EasyMethod_Init);
	// Remove Anti Hack
	ADDSCANRESULT(DR_Check);
	ADDSCANRESULT(RemoveMSCRC_Main_RenderFrame);
	ADDSCANRESULT(RemoveMSCRC_Main_Run_LeaveVM);
	ADDSCANRESULT(RemoveMSCRC_OnEnterField_EnterVM);
	ADDSCANRESULT(RemoveMSCRC_OnEnterField_LeaveVM);
	// Useful Client Edit
	ADDSCANRESULT(WindowMode);
	ADDSCANRESULT(Launcher);
	if (vmprotect) {
		if (result.back().info.VA) {
			result.back().mode = L"JMS v322.0";
			result.back().patch = L"jmp funcion_restore_pe_header";
		}
	}
	ADDSCANRESULT(Ad);
	ADDSCANRESULT(MapleNetwork);
	// GM Command
	ADDSCANRESULT(Extra_GMCommand);
	ADDSCANRESULT(Extra_MapCommand);
	ADDSCANRESULT(Extra_GMChat);
	ADDSCANRESULT(Extra_GMCommand_Lv1);
	ADDSCANRESULT(Extra_GMCommand_Lv2);
	ADDSCANRESULT(Extra_GMCommand_Local);
	ADDSCANRESULT(Extra_MapDropLimit);
	ADDSCANRESULT(Extra_PointItemDropLimit);
	ADDSCANRESULT(Extra_PointItemMultipleDrop);
	// Addr
	ADDSCANRESULT(Addr_SendPacket);
	result.push_back(Find_Addr_EnterSendPacket(f, result.back().info.VA));
	ADDSCANRESULT(Addr_COutPacket);
	ADDSCANRESULT(Addr_Encode1);
	ADDSCANRESULT(Addr_Encode2);
	ADDSCANRESULT(Addr_Encode4);
	ADDSCANRESULT(Addr_EncodeStr);
	ADDSCANRESULT(Addr_EncodeBuffer);
	ADDSCANRESULT(Addr_ProcessPacket);
	ADDSCANRESULT(Addr_Decode1);
	ADDSCANRESULT(Addr_Decode2);
	ADDSCANRESULT(Addr_Decode4);
	ADDSCANRESULT(Addr_DecodeStr);
	ADDSCANRESULT(Addr_DecodeBuffer);
	// Addr test
	ADDSCANRESULT(Addr_StringPool__ms_aString);
	ADDSCANRESULT(Addr_IWzResMan__GetObjectA);
	return result;
}

int g_vm_section = 3;
bool VM_Enter_VMP(Frost &f, ULONG_PTR uResultAddr) {
	AddrInfo ai = f.GetRefAddrRelative(uResultAddr + 0x02, 0x01);
	if (ai.VA == 0) {
		return false;
	}

	if (f.GetSectionNumber(ai.VA) == g_vm_section) {
		return true;
	}

	return false;
}

bool VM_Enter_Themida(Frost &f, ULONG_PTR uResultAddr) {
	AddrInfo ai = f.GetRefAddrRelative(uResultAddr, 0x01);
	if (ai.VA == 0) {
		return false;
	}

	if (f.GetSectionNumber(ai.VA) == g_vm_section) {
		ULONG_PTR uRawAddr =  f.GetRawAddress(uResultAddr);

		if (*(BYTE *)(uRawAddr + 0x02) == 0xE9 && *(BYTE *)(uRawAddr + 0x07) ==  0xCC) {
			return false;
		}

		if (*(WORD *)(uRawAddr + 0x05) == 0x0000) {
			return false;
		}

		return true;
	}

	return false;
}

bool CheckResult(std::vector<AddrInfoEx> &result, AddrInfo &res) {
	for (auto &v : result) {
		if (v.info.VA == res.VA) {
			return true;
		}
	}
	return false;
}

std::vector<AddrInfoEx> VMScanner(Frost &f, int vm_section) {
	std::vector<AddrInfoEx> result;

	AddrInfoEx aix = { L"VM_ENTER", L"" , L"VMProtect" };
	AddrInfo &res = aix.info;

	size_t index = 0;
	g_vm_section = vm_section;
	for (auto &v : f.AobScanAll(L"6A 00 E9", VM_Enter_VMP)) {
		aix.tag = L"VM_ENTER_" + std::to_wstring(index++);
		res = f.GetAddrInfo(v.VA + 0x02);
		result.push_back(aix);
	}

	index = 0;
	aix.mode = L"Themida OR ?";
	for (auto &v : f.AobScanAll(L"E9", VM_Enter_Themida)) {
		if (CheckResult(result, v)) {
			continue;
		}
		aix.tag = L"VM_ENTER_" + std::to_wstring(index++);
		res = v;
		result.push_back(aix);
	}

	return result;
}

bool Poly_check1(Frost &f, ULONG_PTR uResultAddr) {
	AddrInfo ai = f.GetRefAddrRelative(uResultAddr, 0x01);
	if (ai.VA == 0) {
		return false;
	}

	if (f.GetSectionNumber(ai.VA) == g_vm_section) {
		return true;
	}
	return false;
}

// ASPprotect
std::vector<AddrInfoEx> PolyScanner(Frost &f, int vm_section) {
	std::vector<AddrInfoEx> result;

	AddrInfoEx aix = { L"PolyCall", L"" , L"ASProtect" };
	AddrInfo &res = aix.info;

	size_t index = 0;
	g_vm_section = vm_section;
	for (auto &v : f.AobScanAll(L"E8 ?? ?? ?? ?? 90", Poly_check1)) {
		AddrInfo poly = f.GetRefAddrRelative(v.VA, 0x01); // call
		if (!poly.VA) {
			continue;
		}
		// jmp dword ptr
		if (*(WORD *)poly.RA == 0x25FF) {
			aix.patch = L"FF 15 " + DatatoString((BYTE *)(poly.RA + 0x02), 4, true);
		}
		// trampoline
		else if (*(WORD *)(poly.RA + 0x03) == 0x25FF && ((BYTE *)poly.RA)[0] == 0x83 && ((BYTE *)poly.RA)[1] == 0xC4 && ((BYTE *)poly.RA)[2] == 0x04) {
			aix.patch = L"FF 25 " + DatatoString((BYTE *)(poly.RA + 0x05), 4, true);
		}
		else {
			aix.patch = L"ERROR";
		}
		aix.tag = L"PolyCall_" + std::to_wstring(index++);
		res = v;
		result.push_back(aix);
	}

	return result;
}

std::vector<AddrInfoEx> StackClearScanner(Frost &f) {
	std::vector<AddrInfoEx> result;

	// PostBB 1
	{
		AddrInfoEx aix = { L"StackClear", L"EB 2B CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC", L"PostBB_1"};
		AddrInfo &res = aix.info;

		for (auto &v : f.AobScanAll(L"33 DB 33 D2 33 F6 33 FF 33 ED 64 A1 18 00 00 00 8B 48 08 8B 40 04 3B C1 0F 86 0A 00 00 00 83 E8 04 89 18 E9 EE FF FF FF 33 C0 33 C9 C3")) {
			res = v;
			result.push_back(aix);
		}
	}
	// PostBB 2
	{
		AddrInfoEx aix = { L"StackClear", L"EB 24 CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC", L"PostBB_2" };
		AddrInfo &res = aix.info;

		for (auto &v : f.AobScanAll(L"31 DB 31 D2 31 F6 31 FF 31 ED 64 A1 18 00 00 00 8B 48 08 8B 40 04 39 C8 76 07 83 E8 04 89 18 EB F5 31 C0 31 C9 C3")) {
			res = v;
			result.push_back(aix);
		}
	}
	// Pre-BB
	{
		AddrInfoEx aix = { L"StackClear", L"EB 08 CC CC CC CC CC CC CC CC", L"PreBB" };
		AddrInfo &res = aix.info;

		for (auto &v : f.AobScanAll(L"31 C0 89 04 24 83 C4 04 EB F6")) {
			res = v;
			result.push_back(aix);
		}
	}
	// GMS, CMS ONLY
	{
		AddrInfoEx aix = { L"CheapCrash", L"EB 2F CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC", L"pushad" };
		AddrInfo &res = aix.info;

		for (auto &v : f.AobScanAll(L"60 03 C3 03 C1 03 C2 74 02 75 25 EB 18 BE 04 74 76 F7 36 51 2C B3 96 DD BF 57 C0 10 75 43 54 4F 92 8B 09 30 F3 D4 25 10 25 15 52 05 05 58 6F CA 61")) {
			res = v;
			result.push_back(aix);
		}
	}
	// GMS, EMS, CMS
	{
		AddrInfoEx aix = { L"CheapCrash", L"EB 1E CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC", L"Call_0" };
		AddrInfo &res = aix.info;

		for (auto &v : f.AobScanAll(L"29 F7 BB ?? ?? ?? ?? 8B 04 37 8B 0E 35 ?? ?? ?? ?? 39 C1 74 05 58 31 C0 FF D0 83 C6 04 4B 75 E7")) {
			res = v;
			result.push_back(aix);
		}
	}

	return result;
}