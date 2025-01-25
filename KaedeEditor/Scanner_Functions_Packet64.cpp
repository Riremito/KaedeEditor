#include"AobScanner.h"


AddrInfoEx Find_Addr_SendPacket_64(Frost &f) {
	AddrInfoEx aix = { L"CClientSocket::SendPacket" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 54 24 10 48 89 4C 24 08 56 57 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? E9");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_SendPacket_EH_64(Frost &f) {
	AddrInfoEx aix = { L"SendPacket_EH" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 4C 24 08 48 83 EC ?? E8 ?? ?? ?? ?? 48 89 44 24 ?? 48 8B 44 24 ?? 8B 80 ?? ?? ?? ?? 89 44 24 ?? 8B 54 24 ?? 48 8B 4C 24 ?? E8 ?? ?? ?? ?? 48 8B 44 24 ?? 8B 88 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 C0 85 C0 75 17 48 8B 44 24 ?? 8B 88 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 C0 85 C0 74 27 E8 ?? ?? ?? ?? 48 89 44 24 ?? 48 8B 44 24 ?? 8B 80 ?? ?? ?? ?? 89 44 24 ?? 8B 54 24 ?? 48 8B 4C 24 ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 44 24 ?? 48 83 7C 24 ?? 00 74 0F 48 8B 54 24 ?? 48 8B 4C 24 ?? E8");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_COutPacket_64(Frost &f) {
	AddrInfoEx aix = { L"COutPacket::COutPacket" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 5C 24 10 48 89 4C 24 08 57 48 83 EC ?? 48 8B D9 33 FF 48 89 B9");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	res = f.AobScan(L"48 89 5C 24 10 48 89 74 24 18 48 89 4C 24 08 57 48 83 EC ?? 8B FA 48 8B F1 48 83 C1 08 E8 ?? ?? ?? ?? 90 33 C0 89");
	if (res.VA) {
		mode = L"JMS v425.2";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_Encode1_64(Frost &f) {
	AddrInfoEx aix = { L"COutPacket::Encode1" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 5C 24 08 57 48 83 EC ?? 48 8B D9 0F B6 FA 8B 89 ?? ?? ?? ?? 8D 51 01 3B 93 ?? ?? ?? ?? 76");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_Encode2_64(Frost &f) {
	AddrInfoEx aix = { L"COutPacket::Encode2" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ?? 0F B7 F2 48 8B D9 8B 91 ?? ?? ?? ?? 8D 42 02 3B 81 ?? ?? ?? ?? 76");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_Encode4_64(Frost &f) {
	AddrInfoEx aix = { L"COutPacket::Encode4" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ?? 8B F2 48 8B D9 8B 91 ?? ?? ?? ?? 8D 42 04 3B 81 ?? ?? ?? ?? 76");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_Encode8_64(Frost &f) {
	AddrInfoEx aix = { L"COutPacket::Encode8" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ?? 48 8B F2 48 8B D9 8B 91 ?? ?? ?? ?? 8D 42 08 3B 81 ?? ?? ?? ?? 76");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_EncodeStr_64(Frost &f) {
	AddrInfoEx aix = { L"COutPacket::EncodeStr" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 56 48 83 EC ?? 48 8B 02 45 33 F6 48 8B FA 48 8B D9 48 85 C0 74 05 8B 48 FC EB 03 41 8B CE 8B B3 ?? ?? ?? ?? 8D 56 02 03 D1 3B 93 ?? ?? ?? ?? 76");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_EncodeBuffer_64(Frost &f) {
	AddrInfoEx aix = { L"COutPacket::EncodeBuffer" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC ?? 48 8B EA 41 8B F8 8B 91 ?? ?? ?? ?? 48 8B D9 42 8D 04 02 3B 81 ?? ?? ?? ?? 76");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_ProcessPacket_64(Frost &f) {
	AddrInfoEx aix = { L"CClientSocket::ProcessPacket" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 54 24 10 48 89 4C 24 08 48 81 EC ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 ?? ?? ?? ?? ?? ?? ?? 48 8D 4C 24 34 E8");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	res = f.AobScan(L"48 89 54 24 10 48 89 4C 24 08 48 81 EC ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 C0 85 C0 75 05 E9 ?? ?? ?? ?? E9");
	if (res.VA) {
		mode = L"JMS v425.2";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_Decode1_64(Frost &f) {
	AddrInfoEx aix = { L"CInPacket::Decode1" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 5C 24 10 48 89 4C 24 08 57 48 83 EC 50 48 8B D9 8B 79 10 2B 79 1C 48 8B 41 08 48 85 C0 75 18 B9 B5 00 00 00 E8 ?? ?? ?? ?? 48 8B 43 08 48 85 C0 75 05 45 33 C0 EB 09 44 8B 40 FC 45 85 C0 75 0C 33 D2 B9 A1 00 00 00 E8 ?? ?? ?? ?? 8B 4B 1C 8B C1 48 03 43 08 83 FF 01");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_Decode2_64(Frost &f) {
	AddrInfoEx aix = { L"CInPacket::Decode2" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 5C 24 10 48 89 4C 24 08 57 48 83 EC 50 48 8B D9 8B 79 10 2B 79 1C 48 8B 41 08 48 85 C0 75 18 B9 B5 00 00 00 E8 ?? ?? ?? ?? 48 8B 43 08 48 85 C0 75 05 45 33 C0 EB 09 44 8B 40 FC 45 85 C0 75 0C 33 D2 B9 A1 00 00 00 E8 ?? ?? ?? ?? 8B 4B 1C 8B C1 48 03 43 08 83 FF 02");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_Decode4_64(Frost &f) {
	AddrInfoEx aix = { L"CInPacket::Decode4" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 5C 24 10 48 89 4C 24 08 57 48 83 EC 50 48 8B D9 8B 79 10 2B 79 1C 48 8B 41 08 48 85 C0 75 18 B9 B5 00 00 00 E8 ?? ?? ?? ?? 48 8B 43 08 48 85 C0 75 05 45 33 C0 EB 09 44 8B 40 FC 45 85 C0 75 0C 33 D2 B9 A1 00 00 00 E8 ?? ?? ?? ?? 8B 4B 1C 8B C1 48 03 43 08 83 FF 04");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_Decode8_64(Frost &f) {
	AddrInfoEx aix = { L"CInPacket::Decode8" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 5C 24 10 48 89 4C 24 08 57 48 83 EC 50 48 8B D9 8B 79 10 2B 79 1C 48 8B 41 08 48 85 C0 75 18 B9 B5 00 00 00 E8 ?? ?? ?? ?? 48 8B 43 08 48 85 C0 75 05 45 33 C0 EB 09 44 8B 40 FC 45 85 C0 75 0C 33 D2 B9 A1 00 00 00 E8 ?? ?? ?? ?? 8B 4B 1C 8B C1 48 03 43 08 83 FF 08 72 ?? 48");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_DecodeStr_64(Frost &f) {
	AddrInfoEx aix = { L"CInPacket::DecodeStr" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 5C 24 18 48 89 74 24 20 48 89 54 24 10 48 89 4C 24 08 57 41 54 41 55 41 56 41 57 48 83 EC 60 48 8B F2 4C 8B F1 45 33 ED 44 89 6C 24 20 4C 89 2A C7 44 24 20 01 00 00 00 8B 59 10 2B 59 1C 48 8B 41 08 48 85 C0 75 18 B9 B5 00 00 00 E8 ?? ?? ?? ?? 49 8B 46 08 48 85 C0 75");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}

AddrInfoEx Find_Addr_DecodeBuffer_64(Frost &f) {
	AddrInfoEx aix = { L"CInPacket::DecodeBuffer" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 48 89 4C 24 08 41 56 48 83 EC 50 41 8B F0 48 8B DA 48 8B F9 44 8B 71 10 44 2B 71 1C 48 8B 41 08 48 85 C0 75 18 B9 B5 00 00 00 E8");
	if (res.VA) {
		mode = L"TWMS v263.3";
		return aix;
	}

	return aix;
}


std::vector<AddrInfoEx> Scanner_Functions_Packet64(Frost &f) {
	std::vector<AddrInfoEx> result;

	ADDSCANRESULT64(Addr_SendPacket_64);
	ADDSCANRESULT64(Addr_SendPacket_EH_64);
	ADDSCANRESULT64(Addr_COutPacket_64);
	ADDSCANRESULT64(Addr_Encode1_64);
	ADDSCANRESULT64(Addr_Encode2_64);
	ADDSCANRESULT64(Addr_Encode4_64);
	ADDSCANRESULT64(Addr_Encode8_64);
	ADDSCANRESULT64(Addr_EncodeStr_64);
	ADDSCANRESULT64(Addr_EncodeBuffer_64);
	ADDSCANRESULT64(Addr_ProcessPacket_64);
	ADDSCANRESULT64(Addr_Decode1_64);
	ADDSCANRESULT64(Addr_Decode2_64);
	ADDSCANRESULT64(Addr_Decode4_64);
	ADDSCANRESULT64(Addr_Decode8_64);
	ADDSCANRESULT64(Addr_DecodeStr_64);
	ADDSCANRESULT64(Addr_DecodeBuffer_64);
	return result;
}