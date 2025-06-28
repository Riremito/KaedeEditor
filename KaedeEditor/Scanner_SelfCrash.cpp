#include"AobScanner.h"


std::vector<AddrInfoEx> Scanner_SelfCrash(Frost &f) {
	std::vector<AddrInfoEx> result;

	// PostBB 1
	{
		AddrInfoEx aix = { L"StackClear", L"EB 2B CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC", L"PostBB_1" };
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
	// GMS
	{
		AddrInfoEx aix = { L"CheapCrash", L"EB 0C CC CC CC CC CC CC CC CC CC CC CC CC", L"Call_Random" };
		AddrInfo &res = aix.info;

		for (auto &v : f.AobScanAll(L"E8 ?? ?? ?? ?? 64 C7 04 24 00 00 00 00 C3")) {
			res = v;
			result.push_back(aix);
		}
	}
	// Early SendPacket detection
	{
		AddrInfoEx aix = { L"RetAddrCheck", L"3D 00 10 40 00 76 04 3B C3 72 04 90 90 90 90", L"Call_0" };
		AddrInfo &res = aix.info;

		for (auto &v : f.AobScanAll(L"3D 00 10 40 00 76 04 3B C3 72 04 33 C0 FF D0")) {
			res = v;
			result.push_back(aix);
		}
	}
	// TWMS148, EMS89, CMS104
	{
		// set 0x101210 to ptr (MSCRC for SendPacket)
		AddrInfoEx aix = { L"CheapCrash_v2", L"8B 44 24 08 C7 00 10 12 10 00 31 C0 C3", L"Call_Random_v2" };
		AddrInfo &res = aix.info;

		for (auto &v : f.AobScanAll(L"55 8B EC 83 EC 7C 53 56 57 EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 8B 75 08 B9 ?? ?? ?? ?? 31 C0 8D 7D 84 F3 AB 8D 7D 84 C7")) {
			res = v;
			result.push_back(aix);
		}
	}

	return result;
}
