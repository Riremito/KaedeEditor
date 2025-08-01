﻿#include"AobScanner.h"
#include"ScannerOption.h"


std::wstring StrPatchPadding(AddrInfo &res, std::wstring str) {
	std::wstring patch = L"\'" + str + L"\' 00";
	size_t str_len = str.length();
	size_t target_len = strlen((char *)res.RA);
	for (size_t i = str_len; i < target_len; i++) {
		patch += L" 00";
	}
	return patch;
}

bool Find_String_IPs(Frost &f, std::vector<AddrInfoEx> &result) {
	AddrInfoEx aix = { L"ServerIP" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;
	bool is_hit = false;
	// JMS
	res = f.ScanString("61.215.216.38");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"JMS v29";
		result.push_back(aix);
		is_hit = true;
	}
	res = f.ScanString("59.128.93.105");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"JMS v164.0";
		result.push_back(aix);
		is_hit = true;
	}

	res = f.ScanString("111.87.33.105");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"JMS v302.0";
		result.push_back(aix);
		is_hit = true;
	}

	if (is_hit) {
		return true;
	}

	// TWMS
	res = f.ScanString("tw.login.maplestory.gamania.com");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"TWMS v157";
		result.push_back(aix);
		is_hit = true;
	}

	if (is_hit) {
		return true;
	}

	// EMS
	res = f.ScanString("91.202.203.226");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"EMS v55.1";
		result.push_back(aix);
		is_hit = true;
	}
	res = f.ScanString("109.234.73.11");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"EMS v70.1";
		result.push_back(aix);
		is_hit = true;
	}

	if (is_hit) {
		return true;
	}

	// CMS
	res = f.ScanString("mxdlogin.poptang.com");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"CMS v86.1";
		result.push_back(aix);
		is_hit = true;
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

	if (is_hit) {
		return true;
	}

	// KMS
	res = f.ScanString("220.90.204.10");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"KMS v2.109";
		result.push_back(aix);
		is_hit = true;
		// more
		res = f.ScanString("220.90.204.11");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
		}
		res = f.ScanString("220.90.204.12");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
		}
		res = f.ScanString("220.90.204.13");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
		}
		res = f.ScanString("220.90.204.14");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
		}
		res = f.ScanString("220.90.204.15");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
		}
		res = f.ScanString("220.90.204.16");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
		}
		res = f.ScanString("220.90.204.17");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
		}
		res = f.ScanString("220.90.204.18");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
		}
		res = f.ScanString("220.90.204.19");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
		}
		res = f.ScanString("220.90.204.20");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.109";
			result.push_back(aix);
		}
		res = f.ScanString("220.90.204.21");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMSB v1.68";
			result.push_back(aix);
		}
	}

	if (is_hit) {
		return true;
	}

	// KMS v2.183+
	res = f.ScanString("175.207.0.33");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"KMS v2.183";
		result.push_back(aix);
		is_hit = true;
		// more
		res = f.ScanString("175.207.0.34");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.183";
			result.push_back(aix);
		}
		res = f.ScanString("175.207.0.35");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.183";
			result.push_back(aix);
		}
		res = f.ScanString("175.207.0.36");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.183";
			result.push_back(aix);
		}
		res = f.ScanString("175.207.0.37");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.183";
			result.push_back(aix);
		}
		res = f.ScanString("175.207.0.38");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.183";
			result.push_back(aix);
		}
		res = f.ScanString("175.207.0.39");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.183";
			result.push_back(aix);
		}
		res = f.ScanString("175.207.0.40");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.183";
			result.push_back(aix);
		}
		res = f.ScanString("175.207.0.41");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.183";
			result.push_back(aix);
		}
		res = f.ScanString("175.207.0.42");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.183";
			result.push_back(aix);
		}
		res = f.ScanString("175.207.0.43");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"KMS v2.183";
			result.push_back(aix);
		}
	}

	if (is_hit) {
		return true;
	}

	// MSEA
	res = f.ScanString("203.116.196.8");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"MSEA v100";
		result.push_back(aix);
		is_hit = true;
		// more
		res = f.ScanString("203.188.239.82");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"MSEA v100";
			result.push_back(aix);
		}
	}

	if (is_hit) {
		return true;
	}

	// KMST
	res = f.ScanString("61.78.52.30");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"KMST v2.391";
		result.push_back(aix);
		is_hit = true;
	}

	if (is_hit) {
		return true;
	}
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
		is_hit = true;
	}

	if (is_hit) {
		return true;
	}

	// THMS
	res = f.ScanString("61.90.227.132");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"THMS v88";
		result.push_back(aix);
		is_hit = true;
	}

	if (is_hit) {
		return true;
	}

	// GMS
	res = f.ScanString("63.251.217.2");
	if (res.VA) {
		aix.patch = StrPatchPadding(res, L"127.0.0.1");
		mode = L"GMS v72";
		result.push_back(aix);
		is_hit = true;
		// more
		res = f.ScanString("63.251.217.3");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"GMS v72";
			result.push_back(aix);
		}
		res = f.ScanString("63.251.217.4");
		if (res.VA) {
			aix.patch = StrPatchPadding(res, L"127.0.0.1");
			mode = L"GMS v72";
			result.push_back(aix);
		}
	}

	if (is_hit) {
		return true;
	}

	return false;
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

// HackShield
AddrInfoEx Find_HackShield_Init(Frost &f) {
	AddrInfoEx aix = { L"?StartModule@CSecurityClient@@QAEXPAUHWND__@@@Z", L"31 C0 C2 04 00" };
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

	if (GetDEVM()) {
		res = f.AobScan(L"55 8B EC 51 51 56 8B F1 EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E8 ?? ?? ?? ?? 85 C0 74 ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 6A 01");
		if (res.VA) {
			aix.patch = L"31 C0 C3";
			mode = L"GMS v83.1";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_HackShield_EHSvc_Loader_1(Frost &f) {
	AddrInfoEx aix = { L"__AhnHS_StartMonitorA@784", L"31 C0 C2 10 03" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 ?? ?? ?? ?? 33 C0 8D BD ?? ?? ?? ?? F3 AB C7 45 FC ?? ?? ?? ?? 68");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 F8 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 ?? ?? ?? ?? 33 C0 8D BD ?? ?? ?? ?? F3 AB C7 45 FC 00 00 00 00 8B 85 ?? ?? ?? ?? 50 68 04 01 00 00");
	if (res.VA) {
		mode = L"KMS v2.138";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 ?? ?? ?? ?? 33 C0 8D BD ?? ?? ?? ?? F3 AB C7 85 ?? ?? ?? ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 ?? ?? ?? ?? 33 C0 8D BD ?? ?? ?? ?? F3 AB 66 AB AA 8B 85 ?? ?? ?? ?? 50 68 04 01 00 00");
	if (res.VA) {
		mode = L"JMS v308.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_HackShield_EHSvc_Loader_2(Frost &f) {
	AddrInfoEx aix = { L"__AhnHS_InitializeA@24", L"31 C0 C2 18 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 82 00 00 00 33 C0 8D BD ?? ?? ?? ?? F3 AB C7 45 ?? 00 00 00 00 FF 15 ?? ?? ?? ?? 50 E8");
	if (res.VA) {
		mode = L"JMS v164.0";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 B9 ?? ?? ?? ?? 33 C0 8D BD ?? ?? ?? ?? F3 AB");
	if (res.VA) {
		mode = L"JMS v186.1";
		return aix;
	}

	res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 B9 09 00 00 00 33 C0 8D 7D ?? F3 AB");
	if (res.VA) {
		mode = L"JMS v308.0";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_HackShield_HeartBeat(Frost &f) {
	AddrInfoEx aix = { L"?OnCheckClientIntegrityRequest@CSecurityClient@@AAEXAAVCInPacket@@@Z", L"31 C0 C2 04 00" };
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
	AddrInfoEx aix = { L"?StartKeyCrypt@CSecurityClient@@QAEXXZ", L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

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

	res = f.AobScan(L"83 EC 0C 56 8B F1 57 8D 7E ?? 8B CF E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 89 44 24 08 8D 44 24 08 50 FF 15");
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
	AddrInfoEx aix = { L"?ClearKeyCrypt@CSecurityClient@@QAEXXZ", L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

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

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 ?? 64 A3 00 00 00 00 8B F1 89 74 24 ?? C7 06 ?? ?? ?? ?? 8D 7E ?? 8B CF C7 44 24 ?? 08 00 00 00 E8 ?? ?? ?? ?? 33 DB 85 C0 74 ?? E8");
	if (res.VA) {
		mode = L"KMS v2.138";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_HackShield_ASPLunchr(Frost &f) {
	AddrInfoEx aix = { L"?InitKeyCrypt@CSecurityClient@@QAEXXZ", L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

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

	res = f.AobScan(L"83 EC 0C 56 8B F1 57 8D 7E ?? 8B CF E8 ?? ?? ?? ?? 85 C0 75 ?? 68 ?? ?? ?? ?? FF 15");
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
	AddrInfoEx aix = { L"?InitModule@CSecurityClient@@QAEXXZ", L"31 C0 C3" };
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

	res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 84 24 ?? ?? ?? ?? 64 A3 00 00 00 00 8D 69 ?? 8B CD E8 ?? ?? ?? ?? 85 C0 0F 85");
	if (res.VA) {
		mode = L"JMS v188.0";
		return aix;
	}

	if (GetDEVM()) {
		res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 8B D9 EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 8A 15 ?? ?? ?? ?? 31 C0 B9 40 00 00 00 88 95 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? F3 AB 66 AB AA 6A 40 31 C0");
		if (res.VA) {
			mode = L"GMS v83.1";
			return aix;
		}
	}

	return aix;
}

// JMS308 removed ?g_bUseMonitor@@3HA null check and give you crash, thanks!
AddrInfoEx Find_HackShield_SetUserIdA(Frost &f) {
	AddrInfoEx aix = { L"__AhnHS_SetUserIdA@4", L"31 C0 C2 04 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"55 8B EC 83 EC 08 C7 45 FC 00 00 00 00 8B 45 08 89 45 F8 8D 4D FC 51 8D 55 F8 52 6A 13 FF 15 58 16 39 01 25 FF 00 00 00 83 F8 01 74");
	if (res.VA) {
		mode = L"JMS v308.0";
		return aix;
	}

	return aix;
}

// ===== REMOVE GAMEGUARD =====
AddrInfoEx Find_GameGuard_1(Frost &f) {
	AddrInfoEx aix = { L"GameGuard_1" , L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"A1 ?? ?? ?? ?? 53 33 DB 3B C3 74 04 33 C0 5B C3 55 8B 2D");
		if (res.VA) {
			mode = L"KMS v2.65";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_GameGuard_2(Frost &f) {
	AddrInfoEx aix = { L"GameGuard_2" , L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 E8 ?? ?? ?? ?? 3D 55 07 00 00 74");
		if (res.VA) {
			mode = L"KMS v2.65";
			return aix;
		}

		res = f.AobScan(L"55 8B EC 51 51 56 8D 71 0C 8B CE E8 ?? ?? ?? ?? 85 C0 75 2C E8 ?? ?? ?? ?? 3D 55 07 00 00 74");
		if (res.VA) {
			mode = L"KMS v2.71";
			return aix;
		}

		// DEVM
		if (GetDEVM()) {
			res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E8 ?? ?? ?? ?? 3D 55 07 00 00 74");
			if (res.VA) {
				mode = L"GMS v65.1";
				return aix;
			}
		}
	}

	return aix;
}

AddrInfoEx Find_GameGuard_3(Frost &f) {
	AddrInfoEx aix = { L"GameGuard_3" , L"31 C0 C2 04 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 FF 75 08 8B F9 E8 ?? ?? ?? ?? 59 8D 85 ?? ?? ?? ?? 50 C7 85 ?? ?? ?? ?? 94 00 00 00 FF 15 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 02 0F 85");
		if (res.VA) {
			mode = L"KMS v2.65";
			return aix;
		}

		res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 53 8B D9 8D 4B 18 89 4D FC E8 ?? ?? ?? ?? 85 C0 0F 85");
		if (res.VA) {
			mode = L"KMS v2.71";
			return aix;
		}

		// DEVM
		if (GetDEVM()) {
			res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 57 8B F9 EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FF 75 08 E8 ?? ?? ?? ?? 59 8D 85 ?? ?? ?? ?? 50 C7 85 ?? ?? ?? ?? 94 00 00 00 FF 15 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 02 0F 85");
			if (res.VA) {
				mode = L"GMS v65.1";
				return aix;
			}
		}
	}

	return aix;
}

AddrInfoEx Find_GameGuard_4(Frost &f) {
	AddrInfoEx aix = { L"GameGuard_4" , L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 56 8B F1 8B 46 04 57 33 FF 3B C7 74 ?? 89 45 ?? 89 45 ?? 68");
		if (res.VA) {
			mode = L"JMS v141.0";
			return aix;
		}

		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 56 8B F1 57 8D 7E 04 8B CF E8 ?? ?? ?? ?? 85 C0 74");
		if (res.VA) {
			mode = L"KMS v2.65";
			return aix;
		}

		res = f.AobScan(L"55 8B EC 51 51 56 8B F1 57 8D 7E 48 8B CF E8 ?? ?? ?? ?? 85 C0 74 1E 8B CF E8 ?? ?? ?? ?? 50 8D 4D F8 E8 ?? ?? ?? ?? 68");
		if (res.VA) {
			mode = L"KMS v2.71";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_GameGuard_5(Frost &f) {
	AddrInfoEx aix = { L"GameGuard_5" , L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 53 56 8B F1 FF 46 ?? 33 DB 39 5E ?? 0F 8F");
		if (res.VA) {
			mode = L"JMS v141.0";
			return aix;
		}

		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 53 56 8B F1 33 DB 39 5E ?? 57 0F 8F");
		if (res.VA) {
			mode = L"TWMS v43.1";
			return aix;
		}

		res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? 56 8B F1 8D 4E 30 89 4D FC E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? FF 46 7C 39 46 78 0F 8F");
		if (res.VA) {
			mode = L"KMS v2.71";
			return aix;
		}
	}

	return aix;
}

// ===== REMOVE HACKSHIELD =====
// ??0CSecurityClient@@QAE@XZ inside
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

	res = f.AobScan(L"23 C2 57 89 75 F0 A3 ?? ?? ?? ?? 33 FF 57 89 7D FC E8");
	if (res.VA) {
		aix.patch = L"31 C0";
		mode = L"GMS v72.1";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_HackShield_RunningCheck(Frost &f) {
	AddrInfoEx aix = { L"?Update@CSecurityClient@@QAEXXZ" , L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"55 8B EC 51 51 8B 41 1C B9 01 05 01 00 3B C1 7F");
	if (res.VA) {
		mode = L"GMS v72.1";
		return aix;
	}

	return aix;
}

// for vmprotect era
AddrInfoEx Find_HackShield_Packet(Frost &f) {
	AddrInfoEx aix = { L"?SendFullMemoryCheckResult@CClientSocket@@IAEXXZ" , L"jmp funcion_restore_code_section" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 56 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 ?? 64 A3 00 00 00 00 8B F1 6A ?? 8D 4C 24 ?? C6 86 ?? ?? ?? ?? 01 E8 ?? ?? ?? ?? 6A 01");
		if (res.VA) {
			mode = L"JMS v322.0";
			return aix;
		}
	}

	return aix;
}

// for easy method
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
	// ?StopKeyCrypt@CSecurityClient@@QAEXXZ
	result.push_back(AddrInfoEx{ L"EasyMethod_StartKeyCrypt", L"31 C0 C3", L"Easy", f.GetRefAddrRelative(res.VA, 0x01) });
	// ?StartKeyCrypt@CSecurityClient@@QAEXXZ
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

// anti debug
AddrInfoEx Find_DR_Check(Frost &f) {
	AddrInfoEx aix = { L"?DR_check@@YAHPAU_DR_INFO@@PAKPAUHINSTANCE__@@@Z" , L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetDEVM()) {
		res = f.AobScan(L"55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 FC 53 56 57 EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 10 00 01 00 8B 45 08 8B 48 10 81 F1 AD 81 DE 19 81 F9 10 20 00 00 75");
		if (res.VA) {
			mode = L"JMS v308.0";
			return aix;
		}

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
	}

	return aix;
}

AddrInfoEx Find_HideDll(Frost &f) {
	AddrInfoEx aix = { L"?HideDll@@YAXPAUHINSTANCE__@@@Z" , L"31 C0 C3" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	// DEVM
	if (GetDEVM()) {
		res = f.AobScan(L"55 8B EC 51 56 EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 31 D2 89 55 FC 50 64 A1 18 00 00 00 8B 40 30 8B 40 0C 89 45 FC 58");
		if (res.VA) {
			mode = L"GMS v62.1";
			return aix;
		}

		res = f.AobScan(L"55 8B EC 51 51 53 56 57 EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 65 FC 00 50 64 A1 18 00 00 00 8B 40 30 8B 40 0C");
		if (res.VA) {
			mode = L"GMS v84.1";
			return aix;
		}

		res = f.AobScan(L"55 8B EC 83 EC ?? EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 C7 45 FC 00 00 00 00 50 64 A1 18 00 00 00 8B 40 30 8B 40 0C 89 45 FC 58");
		if (res.VA) {
			mode = L"GMS v111.1";
			return aix;
		}
	}

	return aix;
}

// ?RenderFrame@IWzGr2D@@QAEJXZ
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

// ?Run@CWvsApp@@QAEXPAH@Z
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

// ?OnEnterField@CWvsContext@@QAEXXZ
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

	/*
	res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 81 EC ?? ?? ?? ?? 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 8D ?? ?? ?? ?? C7 45 BC 00 00 00 00 33 C0 89 45 C0 89 45 C4 89 45 C8 89 45 CC 89 45 D0 89 45 D4 C7 45 B0 00 00 00 00 33 C9 89 4D B4 89 4D B8 E8");
	if (res.VA) {
		res = f.GetAddrInfo(res.VA + 0x70);
		mode = L"JMS v334";
		return aix;
	}

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

// useful fix
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

	res = f.AobScan(L"89 F1 C7 05 ?? ?? ?? ?? 10 00 00 00 E8 ?? ?? ?? ?? 89 F1 E8");
	if (res.VA) {
		mode = L"GMS v72.1";
		res = f.GetAddrInfo(res.VA + 0x02 + 0x06);
		return aix;
	}

	res = f.AobScan(L"C7 05 ?? ?? ?? ?? 10 00 00 00 8B 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? E8");
	if (res.VA) {
		mode = L"GMS v84.1";
		res = f.GetAddrInfo(res.VA + 0x06);
		return aix;
	}

	res = f.AobScan(L"C7 05 ?? ?? ?? ?? 10 00 00 00 E8");
	if (res.VA) {
		mode = L"GMS v65.1";
		res = f.GetAddrInfo(res.VA + 0x06);
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Launcher(Frost &f) {
	AddrInfoEx aix = { L"?ShowStartUpWnd@@YAHABUStartUpWndParam@@@Z", L"B8 01 00 00 00 C3" };
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
	AddrInfoEx aix = { L"?ShowADBalloon@@YAHABUADBalloonParam@@@Z", L"B8 01 00 00 00 C3"};
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 53 33 DB 39 1D ?? ?? ?? ?? 56 57 74 05 E8 ?? ?? ?? ?? 53 FF 15");
		if (res.VA) {
			mode = L"JMS v147.0";
			return aix;
		}

		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 53 56 57 33 DB 53 FF 15");
		if (res.VA) {
			mode = L"JMS v164.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 64 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 78 64 A3 00 00 00 00 33 ?? 5? FF 15");
		if (res.VA) {
			mode = L"JMS v188.0";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_AdSpace(Frost &f) {
	AddrInfoEx aix = { L"AdSpace", L"EB" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"74 4B 8B 4D FC 89 4F 14 8B 4D 0C 6A 05 50 89 4F 18 FF 15");
		if (res.VA) {
			mode = L"GMS v62.1";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_MapleNetwork(Frost &f) {
	AddrInfoEx aix = { L"MapleNetwork", L"31 C0 C2 08 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 53 56 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 ?? 64 A3 00 00 00 00 8B F1 8A 5C 24 ?? 8A 44 24 ?? 88 5E ?? 88 46 ?? 80 FB 01 75");
		if (res.VA) {
			mode = L"JMS v194.0";
			return aix;
		}

		res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 ?? 64 A3 00 00 00 00 8B E9 33 D2 89 54 24 ?? 8B 0D ?? ?? ?? ?? 85 C9 74");
		if (res.VA) {
			mode = L"JMS v302.0";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_WzRSAEncryptStringForLoginPassword(Frost &f) {
	AddrInfoEx aix = { L"WzRSAEncryptStringForLoginPassword", L"EB 14 CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC 83 C4 0C 6A FF 8B 45 08 FF 30 EB 00" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"8D 85 ?? ?? ?? ?? 50 FF 75 0C FF 75 F0 FF 75 10 FF 15 ?? ?? ?? ?? 83 C4 1C 6A FF 8D 85 ?? ?? ?? ?? 50");
		if (res.VA) {
			mode = L"JMS v147.0";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_JumpDown(Frost &f) {
	AddrInfoEx aix = { L"JumpDown", L"EB" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"FF 15 ?? ?? ?? ?? 8B 4D ?? 8B 41 ?? 83 78 ?? 00 C6 45 ?? 01 74 ?? 80 65 ?? 00 85 C9 74");
		if (res.VA) {
			res = f.GetAddrInfo(res.VA + 0x14);
			mode = L"JMS v147.0";
			return aix;
		}
	}

	return aix;
}

// GMS v6X, crash after close window
AddrInfoEx Find_TerminateFix_1(Frost &f) {
	AddrInfoEx aix = { L"TerminateFix_1", L"EB" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"C7 45 FC 0B 00 00 00 74 14 83 60 28 00 8B 0D ?? ?? ?? ?? E8");
		if (res.VA) {
			res = f.GetAddrInfo(res.VA + 0x07);
			mode = L"GMS v65.1";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_TerminateFix_2(Frost &f) {
	AddrInfoEx aix = { L"TerminateFix_2", L"EB 0D 90 90 90 90 90 90 90 90 90 90 90 90 90 EB" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"BB ?? ?? ?? ?? 56 8B CB E8 ?? ?? ?? ?? 84 C0 75 ?? A1");
		if (res.VA) {
			mode = L"GMS v65.1";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_TerminateFix_3(Frost &f) {
	AddrInfoEx aix = { L"TerminateFix_3", L"90 90 90 90 90" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"80 65 FC 00 8D 4E 20 E8 ?? ?? ?? ?? 8B 4D F4 83 25 ?? ?? ?? ?? 00 5E 64 89 0D 00 00 00 00 C9 C3");
		if (res.VA) {
			res = f.GetAddrInfo(res.VA + 0x07);
			mode = L"GMS v65.1";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_TerminateFix_4(Frost &f) {
	AddrInfoEx aix = { L"TerminateFix_4", L"EB" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"83 7C 24 0C 00 53 8B 5C 24 14 89 3D ?? ?? ?? ?? 88 1D ?? ?? ?? ?? 75");
		if (res.VA) {
			res = f.GetAddrInfo(res.VA + 0x16);
			mode = L"GMS v65.1";
			return aix;
		}
	}

	return aix;
}


// GMS v83+
AddrInfoEx Find_NMCO_1_Start(Frost &f) {
	AddrInfoEx aix = { L"NMCO_1_Start", L"" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"57 68 C9 00 00 00 FF 75 0C FF 75 08 E8");
		if (res.VA) {
			mode = L"GMS v83.1";
			return aix;
		}
	}

	return aix;
}


AddrInfoEx Find_NMCO_1_End(Frost &f) {
	AddrInfoEx aix = { L"NMCO_1_End", L"" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"6A 01 5B 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? C7 45 ?? 02 00 00 00 E8");
		if (res.VA) {
			res = f.GetAddrInfo(res.VA + 0x03);
			mode = L"GMS v83.1";
			return aix;
		}
	}

	return aix;
}


AddrInfoEx Find_NMCO_2_Start(Frost &f) {
	AddrInfoEx aix = { L"NMCO_2_Start", L"" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"51 8B CC 89 65 ?? 83 CE FF 56 FF 75 0C C6 45 ?? 03 89 39 E8");
		if (res.VA) {
			mode = L"GMS v83.1";
			return aix;
		}
	}

	return aix;
}


std::vector<AddrInfoEx> Scanner_Main(Frost &f) {
	std::vector<AddrInfoEx> result;
	bool vmprotect = false;
	bool is_gameguard_removal_faield = false;
	bool is_hackshield_removal_failed = false;
	bool is_vmprotect = false;
	bool is_NMCO_failed = false;

	// Login Server IP
	Find_String_IPs(f, result);
	// Game Guard Removal
	{
		ADDSCANRESULT(GameGuard_1);
		CheckScanState(is_gameguard_removal_faield);
		if (!is_gameguard_removal_faield) {
			ADDSCANRESULT(GameGuard_2);
			CheckScanState(is_gameguard_removal_faield);
			ADDSCANRESULT(GameGuard_3);
			CheckScanState(is_gameguard_removal_faield);
			ADDSCANRESULT(GameGuard_4);
			CheckScanState(is_gameguard_removal_faield);
			ADDSCANRESULT(GameGuard_5);
			CheckScanState(is_gameguard_removal_faield);
		}
	}
	// HackShield Removal Method 1, this was originally written for early post-BB version of JMS/EMS and this also works for KMS.
	if(is_gameguard_removal_faield) {
		ADDSCANRESULT(HackShield_Init);
		CheckScanState(is_hackshield_removal_failed);
		ADDSCANRESULT(HackShield_EHSvc_Loader_1);
		CheckScanState(is_hackshield_removal_failed);
		ADDSCANRESULT(HackShield_EHSvc_Loader_2);
		CheckScanState(is_hackshield_removal_failed);
		ADDSCANRESULT(HackShield_HeartBeat); // this is not needed.
		ADDSCANRESULT(HackShield_MKD25tray);
		CheckScanState(is_hackshield_removal_failed);
		ADDSCANRESULT(HackShield_Autoup);
		CheckScanState(is_hackshield_removal_failed);
		ADDSCANRESULT(HackShield_ASPLunchr);
		CheckScanState(is_hackshield_removal_failed);
		ADDSCANRESULT(HackShield_HSUpdate);
		CheckScanState(is_hackshield_removal_failed);
		ADDSCANRESULT(HackShield_SetUserIdA); // JMS308+
	}
	// HackShield Removal Method 2, null ptr check exploit.
	if (is_hackshield_removal_failed) {
		is_hackshield_removal_failed = false;
		ADDSCANRESULT(HackShield_NullPtr);
		CheckScanState(is_hackshield_removal_failed);
		ADDSCANRESULT(HackShield_RunningCheck);
		CheckScanState(is_hackshield_removal_failed);
		ADDSCANRESULT(HackShield_Packet); // high version
		if (result.back().info.VA) {
			is_vmprotect = true;
		}
	}
	// HackShield Removal Method 3, HackShield/XignCode/BlackCipher Removal by chuichui, written for TWMS and others.
	if (is_hackshield_removal_failed) {
		is_hackshield_removal_failed = false;
		Find_Addr_EasyMethod(f, result);
		//ADDSCANRESULT(EasyMethod_StartKeyCrypt);
		//ADDSCANRESULT(EasyMethod_StopKeyCrypt);
		//ADDSCANRESULT(EasyMethod_Init);
	}

	ADDSCANRESULT(RemoveMSCRC_Main_RenderFrame);
	ADDSCANRESULT(RemoveMSCRC_Main_Run_LeaveVM);
	ADDSCANRESULT(RemoveMSCRC_OnEnterField_EnterVM);
	ADDSCANRESULT(RemoveMSCRC_OnEnterField_LeaveVM);

	// Remove Anti Hack
	ADDSCANRESULT(Check_Language);
	ADDSCANRESULT(Check_Mutex);
	ADDSCANRESULT(DR_Check);
	ADDSCANRESULT(HideDll);
	// Useful Client Edit
	ADDSCANRESULT(Ad);
	ADDSCANRESULT(AdSpace);
	ADDSCANRESULT(MapleNetwork);
	ADDSCANRESULT(WindowMode);
	ADDSCANRESULT(Launcher);
	ADDSCANRESULT(WzRSAEncryptStringForLoginPassword);
	// NMCO, GMS Login
	{
		ADDSCANRESULT(NMCO_1_Start);
		CheckScanState(is_NMCO_failed);
		if (!is_NMCO_failed) {
			ADDSCANRESULT(NMCO_1_End);
			ADDSCANRESULT(NMCO_2_Start);
		}
	}
	// Bug Fix
	ADDSCANRESULT(JumpDown);
	ADDSCANRESULT(TerminateFix_1);
	ADDSCANRESULT(TerminateFix_2);
	ADDSCANRESULT(TerminateFix_3);
	ADDSCANRESULT(TerminateFix_4);

	// for JMS high version localhost script.
	if (vmprotect) {
		if (result.back().info.VA) {
			result.back().mode = L"JMS v322.0";
			result.back().patch = L"jmp funcion_restore_pe_header";
		}
	}
	return result;
}
