#include"AobScanner.h"
#include"ScannerOption.h"


AddrInfoEx Find_Addr_SendPacket(Frost &f) {
	AddrInfoEx aix = { L"?SendPacket@CClientSocket@@QAEXABVCOutPacket@@@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 53 56 8B F1 8D 9E ?? ?? ?? ?? 8B CB 89 5D ?? E8 ?? ?? ?? ?? 8B 46 ?? 33 C9 3B C1 89 4D ?? 0F 84");
		if (res.VA) {
			mode = L"JMS v131.0";
			return aix;
		}

		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 53 56 8B F1 8D 9E ?? ?? ?? ?? 57 8B CB 89 5D ?? E8 ?? ?? ?? ?? 8B 46 ?? 33 FF 3B C7");
		if (res.VA) {
			mode = L"JMS v164.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
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
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 4D E8 A1 ?? ?? ?? ?? 05 ?? ?? ?? ?? 8B 40 1C 05 ?? ?? ?? ?? 89 45 ?? C7 45 ?? 00 00 00 00 E9");
		if (res.VA) {
			mode = L"CMS v99.1";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2006) {
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
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 ?? 64 A3 00 00 00 00 8B F9 8D 47 ?? 50 8D 4C 24 ?? E8");
		if (res.VA) {
			mode = L"KMS v2.114";
			return aix;
		}

		res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 ?? 64 A3 00 00 00 00 8B F9 8D 44 24 ?? 50 8D 8F ?? ?? ?? ?? 51 8D 4C 24 ?? E8 ?? ?? ?? ?? 8B 47 08 C7 44 24 ?? 00 00 00 00 85 C0 0F 84");
		if (res.VA) {
			mode = L"KMS v2.160";
			return aix;
		}

		res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 ?? 64 A3 00 00 00 00 8B F9 50 33 C0 3B 05 ?? ?? ?? ?? 75 12 EB 00 64 A1 18 00 00 00 8B 40 24");
		if (res.VA) {
			mode = L"KMS v2.174";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 57 8B F9 8D B7 ?? ?? ?? ?? 8B CE 89 75 ?? E8 ?? ?? ?? ?? 8B 47 08 33 C9 3B C1 89 4D ?? 74");
		if (res.VA) {
			mode = L"THMS v87.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 51 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 ?? 64 A3 00 00 00 00 8B F1 8D 86 ?? ?? ?? ?? 50 8D 4C 24 ?? E8 ?? ?? ?? ?? 8B 46 08 C7 44 24 ?? 00 00 00 00 85 C0 74");
		if (res.VA) {
			mode = L"THMS v88.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 57 8B F9 8D 77 ?? 8B CE 89 75 ?? E8 ?? ?? ?? ?? 8B 47 08 33 C9 3B C1 89 4D ?? 74");
		if (res.VA) {
			mode = L"BMS v24.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"6A 04 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F9 8D 77 ?? 8B CE 89 75 ?? E8 ?? ?? ?? ?? 8B 47 08 33 C9 89 4D ?? 3B C1 74");
		if (res.VA) {
			mode = L"TWMS v122.1";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 53 56 8B F1 8D 9E ?? ?? ?? ?? 57 8B CB 89 5D ?? E8 ?? ?? ?? ?? 8B 46 08 33 FF 3B C7 89 7D ?? 0F 84");
		if (res.VA) {
			mode = L"EMS v55.1";
			return aix;
		}
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 1C 53 56 8B F1 8B 46 18 33 DB 3B C3 0F 84 ?? ?? ?? ?? 83 F8 FF 0F 84 ?? ?? ?? ?? 39 5E 24 0F 85");
		if (res.VA) {
			mode = L"KMS v2.1";
			return aix;
		}
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 58 57 8B F9 8B 47 08 85 C0 0F 84 ?? ?? ?? ?? 83 F8 FF 0F 84 ?? ?? ?? ?? 83 7F 14 00 0F 85");
		if (res.VA) {
			mode = L"KMS v1.68";
			return aix;
		}
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

	// 引数1
	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 56 8B F1 83 66 04 00 8D 45 ?? 50 8D 4E 04 68 00 01 00 00 89 75 ?? E8 ?? ?? ?? ?? FF 75 08 83 65 ?? 00 8B CE E8");
		if (res.VA) {
			mode = L"JMS v164.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
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

		res = f.AobScan(L"6A 04 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F1 89 75 ?? 8D 45 ?? 50 8D 4E 04 83 21 00 68 00 01 00 00 E8 ?? ?? ?? ?? FF 75 08 83 65 FC 00 8B CE E8");
		if (res.VA) {
			mode = L"TWMS v122.1";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2006) {
		// 引数2
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 56 8B F1 83 66 04 00 8D 45 ?? 50 8D 4E 04 68 00 01 00 00 89 75 ?? E8 ?? ?? ?? ?? FF 75 0C 83 65 ?? 00 FF 75 08 8B CE E8");
		if (res.VA) {
			mode = L"JMS v131.0";
			return aix;
		}
		// 引数3
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 56 8B F1 83 66 04 00 8D 45 ?? 50 8D 4E 04 68 00 01 00 00 89 75 ?? E8 ?? ?? ?? ?? FF 75 10 83 65 ?? 00 FF 75 0C 8B CE FF 75 08 E8");
		if (res.VA) {
			mode = L"GMS v62.1";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Addr_Encode1(Frost &f) {
	AddrInfoEx aix = { L"?Encode1@COutPacket@@QAEXE@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"56 8B F1 6A 01 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 8A 54 24 08 88 14 08 FF 46 08 5E C2 04 00");
		if (res.VA) {
			mode = L"JMS v164.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"56 8B F1 8B 46 04 57 8D 7E 04 85 C0 74 03 8B 40 FC 8B 4E 08 41 3B C8 76 1E 8B 07 85 C0 74 03 8B 40 FC 03 C0 3B C8 77 FA 8D 4C 24 0C 51 6A 00 50 8B CF E8");
		if (res.VA) {
			mode = L"JMS v188.0";
			return aix;
		}

		res = f.AobScan(L"56 6A 01 8B F1 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 8A 54 24 08 88 14 08 FF 46 08 5E C2 04 00");
		if (res.VA) {
			mode = L"TWMS v122.1";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Addr_Encode2(Frost &f) {
	AddrInfoEx aix = { L"?Encode2@COutPacket@@QAEXG@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"56 8B F1 6A 02 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 66 8B 54 24 08 66 89 14 08 83 46 08 02 5E C2 04 00");
		if (res.VA) {
			mode = L"JMS v164.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"56 8B F1 8B 46 04 57 8D 7E 04 85 C0 74 03 8B 40 FC 8B 4E 08 83 C1 02 3B C8 76 1E 8B 07 85 C0 74 03 8B 40 FC 03 C0 3B C8 77 FA 8D 4C 24 0C 51 6A 00 50 8B CF E8 ?? ?? ?? ?? 8B 56 08 8B 07 66 8B 4C 24 0C 66 89 0C 02 83 46 08 02 5F 5E C2 04 00");
		if (res.VA) {
			mode = L"JMS v188.0";
			return aix;
		}

		res = f.AobScan(L"56 6A 02 8B F1 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 66 8B 54 24 08 66 89 14 08 83 46 08 02 5E C2 04 00");
		if (res.VA) {
			mode = L"TWMS v122.1";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Addr_Encode4(Frost &f) {
	AddrInfoEx aix = { L"?Encode4@COutPacket@@QAEXK@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"56 8B F1 6A 04 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 8B 54 24 08 89 14 08 83 46 08 04 5E C2 04 00");
		if (res.VA) {
			mode = L"JMS v164.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"56 8B F1 8B 46 04 57 8D 7E 04 85 C0 74 03 8B 40 FC 8B 4E 08 83 C1 04 3B C8 76 1E 8B 07 85 C0 74 03 8B 40 FC 03 C0 3B C8 77 FA 8D 4C 24 0C 51 6A 00 50 8B CF E8 ?? ?? ?? ?? 8B 56 08 8B 07 8B 4C 24 0C 89 0C 02 83 46 08 04 5F 5E C2 04 00");
		if (res.VA) {
			mode = L"JMS v188.0";
			return aix;
		}

		res = f.AobScan(L"56 6A 04 8B F1 E8 ?? ?? ?? ?? 8B 4E 08 8B 46 04 8B 54 24 08 89 14 08 83 46 08 04 5E C2 04 00");
		if (res.VA) {
			mode = L"TWMS v122.1";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Addr_EncodeStr(Frost &f) {
	AddrInfoEx aix = { L"?EncodeStr@COutPacket@@QAEXV?$ZXString@D@@@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 8B F1 8B 45 08 83 65 FC 00 85 C0 74 05 8B 40 FC EB 02 33 C0 83 C0 02 50 8B CE E8");
		if (res.VA) {
			mode = L"JMS v164.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 51 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 10 64 A3 00 00 00 00 8B F1 8B 44 24 20 C7 44 24 18 00 00 00 00 85 C0 74");
		if (res.VA) {
			mode = L"JMS v188.0";
			return aix;
		}

		res = f.AobScan(L"6A 04 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F1 8B 45 08 83 65 FC 00 85 C0 74 05 8B 40 FC EB 02 33 C0 83 C0 02 50 8B CE");
		if (res.VA) {
			mode = L"TWMS v122.1";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Addr_EncodeBuffer(Frost &f) {
	AddrInfoEx aix = { L"?EncodeBuffer@COutPacket@@QAEXPBXI@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"56 57 8B 7C 24 10 8B F1 57 E8 ?? ?? ?? ?? 8B 46 04 03 46 08 57 FF 74 24 10 50 E8 ?? ?? ?? ?? 01 7E 08 83 C4 0C 5F 5E C2 08 00");
		if (res.VA) {
			mode = L"JMS v164.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"53 56 8B F1 8B 46 04 57 8D 7E 04 85 C0 74 03 8B 40 FC 8B 4E 08 8B 5C 24 14 03 CB 3B C8 76 1E 8B 07 85 C0 74 03 8B 40 FC 03 C0 3B C8 77 FA 8D 54 24 14 52 6A 00 50 8B CF E8 ?? ?? ?? ?? 8B 4E 08 8B 44 24 10 03 0F 53 50 51 E8 ?? ?? ?? ?? 01 5E 08 83 C4 0C 5F 5E 5B C2 08 00");
		if (res.VA) {
			mode = L"JMS v188.0";
			return aix;
		}

		res = f.AobScan(L"56 FF 74 24 0C 8B F1 E8 ?? ?? ?? ?? 8B 46 04 8B 4E 08 03 C8 51 FF 74 24 10 FF 74 24 10 E8 ?? ?? ?? ?? 01 46 08 83 C4 0C 5E C2 08 00");
		if (res.VA) {
			mode = L"TWMS v122.1";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Addr_ProcessPacket(Frost &f) {
	AddrInfoEx aix = { L"?ProcessPacket@CClientSocket@@IAEXAAVCInPacket@@@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 A1 ?? ?? ?? ?? 56 57 8B F9 8D 4D EC 89 45 F0 E8 ?? ?? ?? ?? 8B 75 08 83 65 FC 00 8B CE E8 ?? ?? ?? ?? 0F B7");
		if (res.VA) {
			mode = L"JMS v164.0";
			return aix;
		}
		// header 1 byte
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 A1 ?? ?? ?? ?? 56 57 8B F9 8D 4D EC 89 45 F0 E8 ?? ?? ?? ?? 8B 75 08 83 65 FC 00 8B CE E8 ?? ?? ?? ?? 0F B6");
		if (res.VA) {
			mode = L"KMS v2.55";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 08 53 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 18 64 A3 00 00 00 00 8B F9 8B 1D ?? ?? ?? ?? 89 5C 24 14 85 DB 74");
		if (res.VA) {
			mode = L"JMS v188.0";
			return aix;
		}

		res = f.AobScan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 ?? 64 A3 00 00 00 00 8B ?? 8B 2D ?? ?? ?? ?? 89 6C 24 ?? 85 ED 74");
		if (res.VA) {
			mode = L"KMS v2.183";
			return aix;
		}

		res = f.AobScan(L"6A 08 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F9 68 ?? ?? ?? ?? 8D 4D EC E8 ?? ?? ?? ?? 8B 75 08 83 65 FC 00 8B CE E8 ?? ?? ?? ?? 0F B7 C0");
		if (res.VA) {
			mode = L"TWMS v122.1";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 A1 ?? ?? ?? ?? 53 56 8B D9 57 8D 4D ?? 89 45 ?? E8 ?? ?? ?? ?? 8B 7D 08 83 65 FC 00 8B CF E8 ?? ?? ?? ?? 33 F6 66 8B F0 8B C6 83 E8 ?? 0F 84");
		if (res.VA) {
			mode = L"EMS v70.1";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Addr_Decode1(Frost &f) {
	AddrInfoEx aix = { L"?Decode1@CInPacket@@QAEEXZ" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 0F B7 51 0C 8B 41 08 83 65 FC 00 53 56 8B 71 14 2B D6 57 03 C6 83 FA 01");
		if (res.VA) {
			mode = L"JMS v164.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 14 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 65 F0 89 4D E8 0F B7 41 0C 8B 51 14 8B 71 08 2B C2 C7 45 FC 00 00 00 00 83 F8 01");
		if (res.VA) {
			mode = L"JMS v188.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"55 8B EC 51 8B 51 ?? 8B 41 ?? 56 0F B7 71 ?? 2B F2 03 C2 83 FE 01 5E 73 ?? 68");
		if (res.VA) {
			mode = L"THMS v87.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"6A 14 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F1 89 75 E8 0F B7 56 0C 8B 46 14 8B 4E 08 83 65 FC 00 2B D0 52 03 C1 50 8D 45 EF 50 E8 ?? ?? ?? ?? 83 C4 0C 01 46 14 8A 45 EF E8 ?? ?? ?? ?? C3");
		if (res.VA) {
			mode = L"TWMS v122.1";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Addr_Decode2(Frost &f) {
	AddrInfoEx aix = { L"?Decode2@CInPacket@@QAEGXZ" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 0F B7 51 0C 8B 41 08 83 65 FC 00 53 56 8B 71 14 2B D6 57 03 C6 83 FA 02");
		if (res.VA) {
			mode = L"JMS v164.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 14 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 65 F0 89 4D E8 0F B7 41 0C 8B 51 14 8B 71 08 2B C2 C7 45 FC 00 00 00 00 83 F8 02");
		if (res.VA) {
			mode = L"JMS v188.0";
			return aix;
		}

		res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC ?? 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 ?? 64 A3 00 00 00 00 89 65 ?? 89 4D ?? 8B 51 18 8B 41 0C 8B 71 08 2B C2 C7 45 ?? 00 00 00 00 83 F8 02 73");
		if (res.VA) {
			mode = L"KMS v2.183";
			return aix;
		}

		res = f.AobScan(L"6A 14 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F1 89 75 E8 0F B7 56 0C 8B 46 14 8B 4E 08 83 65 FC 00 2B D0 52 03 C1 50 8D 45 EC 50 E8 ?? ?? ?? ?? 83 C4 0C 01 46 14 66 8B 45 EC E8 ?? ?? ?? ?? C3");
		if (res.VA) {
			mode = L"TWMS v122.1";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"55 8B EC 51 8B 51 14 8B 41 08 56 0F B7 71 0C 2B F2 03 C2 83 FE 02 5E 73 ?? 68");
		if (res.VA) {
			mode = L"BMS v24.0";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Addr_Decode4(Frost &f) {
	AddrInfoEx aix = { L"?Decode4@CInPacket@@QAEKXZ" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 0F B7 51 0C 8B 41 08 83 65 FC 00 53 56 8B 71 14 2B D6 57 03 C6 83 FA 04");
		if (res.VA) {
			mode = L"JMS v164.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 14 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 65 F0 89 4D E8 0F B7 41 0C 8B 51 14 8B 71 08 2B C2 C7 45 FC 00 00 00 00 83 F8 04");
		if (res.VA) {
			mode = L"JMS v188.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"55 8B EC 51 8B 51 14 8B 41 08 56 0F B7 71 0C 2B F2 03 C2 83 FE 04 5E 73 ?? 68");
		if (res.VA) {
			mode = L"BMS v24.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"6A 14 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F1 89 75 E8 0F B7 56 0C 8B 46 14 8B 4E 08 83 65 FC 00 2B D0 52 03 C1 50 8D 45 EC 50 E8 ?? ?? ?? ?? 83 C4 0C 01 46 14 8B 45 EC E8 ?? ?? ?? ?? C3");
		if (res.VA) {
			mode = L"TWMS v122.1";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Addr_DecodeStr(Frost &f) {
	AddrInfoEx aix = { L"?DecodeStr@CInPacket@@QAE?AV?$ZXString@D@@XZ" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 18 53 56 57 89 65 F0 6A 01 33 FF 8B F1 5B");
		if (res.VA) {
			mode = L"JMS v164.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 14 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 65 F0 8B F1 89 75 E8 C7 45 EC 00 00 00 00 8B 7D 08 B8 01 00 00 00 89 45 FC C7 07 00 00 00 00 0F B7 56 0C 8B 4E 08 89 45 EC 8B 46 14 2B D0 52 03 C1 50 57 E8");
		if (res.VA) {
			mode = L"JMS v188.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 83 65 ?? 00 83 65 ?? 00 56 57 8B F1 8B 46 14 0F B7 4E 0C 6A 01");
		if (res.VA) {
			mode = L"BMS v24.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"6A 14 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F1 89 75 E8 83 65 EC 00 8B 7D 08 83 27 00 33 C0 40 89 45 FC 0F B7 56 0C 8B 4E 08 89 45 EC 8B 46 14 2B D0 52 03 C1 50 57 E8 ?? ?? ?? ?? 83 C4 0C 01 46 14 8B C7 E8 ?? ?? ?? ?? C2 04 00");
		if (res.VA) {
			mode = L"TWMS v122.1";
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find_Addr_DecodeBuffer(Frost &f) {
	AddrInfoEx aix = { L"?DecodeBuffer@CInPacket@@QAEXPAXI@Z" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 14 83 65 FC 00 53 56 8B F1 0F B7 46 0C");
		if (res.VA) {
			mode = L"JMS v164.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 14 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 65 F0 8B F1 89 75 E8 0F B7 46 0C 8B 4E 14 8B 56 08 8B 7D 0C 2B C1 03 CA C7 45 FC 00 00 00 00 3B C7 73");
		if (res.VA) {
			mode = L"JMS v188.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2006) {
		res = f.AobScan(L"55 8B EC 56 8B F1 0F B7 56 0C 8B 4E 14 8B 46 08 57 8B 7D 0C 2B D1 03 C1 3B D7 73 ?? 68");
		if (res.VA) {
			mode = L"BMS v24.0";
			return aix;
		}
	}

	if (GetCFlag() & CF_VS2008) {
		res = f.AobScan(L"6A 10 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F1 89 75 EC 0F B7 56 0C 8B 46 14 8B 4E 08 83 65 FC 00 2B D0 52 03 C1 50 FF 75 0C FF 75 08 E8 ?? ?? ?? ?? 83 C4 10 01 46 14 E8 ?? ?? ?? ?? C2 08 00");
		if (res.VA) {
			mode = L"TWMS v122.1";
			return aix;
		}
	}

	return aix;
}


std::vector<AddrInfoEx> Scanner_Functions_Packet(Frost &f) {
	std::vector<AddrInfoEx> result;

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
	return result;
}