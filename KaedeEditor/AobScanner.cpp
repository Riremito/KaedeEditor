#include"AobScanner.h"

#define AOB_DEC_KEY L"D6 DE 75 86 46 64 A3 71 E8 E6 7B D3 33 30 E7 2E"
AddrInfo FindDecKEY(Frost &f) {
	return f.AobScan(AOB_DEC_KEY);
}

AddrInfo FindArray(Frost &f, std::wstring &msg) {
	AddrInfo ai = { 0 };
	// x64
	if (f.Isx64()) {
		AddrInfo StringPoolRefAddr = f.AobScan(L"48 81 EC ?? ?? ?? ?? 4? 8? ?? 48 63 C2 48 8D ?? ?? ?? ?? ?? 4? 8? ?? C?"); // JMS v425.1
		if (StringPoolRefAddr.VA) {
			msg = L"Aob = JMS v425";
			return f.GetAddrInfo(StringPoolRefAddr.VA + 0x0D + *(signed long int *)(StringPoolRefAddr.RA + 0x0D + 0x03) + 0x07);
		}
		StringPoolRefAddr = f.AobScan(L"48 83 EC ?? 4? 8? ?? 48 63 C2 48 8D ?? ?? ?? ?? ?? 4? 8? ?? C?"); // KMS v2.388.3, MSEA v234.1, TWMS v261.4
		if (StringPoolRefAddr.VA) {
			msg = L"Aob = TWMS v261";
			return f.GetAddrInfo(StringPoolRefAddr.VA + 0x0A + *(signed long int *)(StringPoolRefAddr.RA + 0x0A + 0x03) + 0x07);
		}
		StringPoolRefAddr = f.AobScan(L"75 ?? 4C 8D 25 ?? ?? ?? ?? 49 8B 04 EC 4C 0F BE 38 BA 08 00 00 00 48 8D 0D ?? ?? ?? ?? E8"); // KMS v2.362.3
		if (StringPoolRefAddr.VA) {
			msg = L"Aob = KMS v2.362.3";
			return f.GetAddrInfo(StringPoolRefAddr.VA + 0x02 + *(signed long int *)(StringPoolRefAddr.RA + 0x02 + 0x03) + 0x07);
		}
		StringPoolRefAddr = f.AobScan(L"0F 85 ?? ?? ?? ?? 48 8D 2D ?? ?? ?? ?? 4A 8B 44 FD 00 48 0F BE 18 48 89 5C 24 ?? BA 08 00 00 00 48 8D 0D ?? ?? ?? ?? E8"); // JMS v410.2
		if (StringPoolRefAddr.VA) {
			msg = L"Aob = JMS v410.2";
			return f.GetAddrInfo(StringPoolRefAddr.VA + 0x06 + *(signed long int *)(StringPoolRefAddr.RA + 0x06 + 0x03) + 0x07);
		}
		StringPoolRefAddr = f.AobScan(L"0F 85 ?? ?? ?? ?? 4? 8D 2D ?? ?? ?? ?? 4? 8B ?? 2? 48 0F BE 00 48 89 ?? ?? ?? BA 08 00 00 00 48 8D 0D ?? ?? ?? ?? E8"); // JMS v413.1
		if (StringPoolRefAddr.VA) {
			msg = L"Aob = JMS v413.1";
			return f.GetAddrInfo(StringPoolRefAddr.VA + 0x06 + *(signed long int *)(StringPoolRefAddr.RA + 0x06 + 0x03) + 0x07);
		}
		return ai;
	}
	// x86
	AddrInfo StringPoolRefAddr = f.AobScan(L"75 ?? 8B ?? ?? ?? ?? ?? 0F BE ?? 6A 04"); // JMS v186.1
	if (StringPoolRefAddr.VA) {
		msg = L"Aob = JMS v186";
		return f.GetAddrInfo(*(DWORD *)(StringPoolRefAddr.RA + 0x02 + 0x02));
	}
	StringPoolRefAddr = f.AobScan(L"75 ?? 8B ?? ?? ?? ?? ?? ?? 0F BE ?? 6A 04"); // JMS v194.0
	if (StringPoolRefAddr.VA) {
		msg = L"Aob = JMS v194";
		return f.GetAddrInfo(*(DWORD *)(StringPoolRefAddr.RA + 0x02 + 0x03));
	}
	StringPoolRefAddr = f.AobScan(L"0F 85 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? 0F BE ?? 6A 04"); // CMS v86.1
	if (StringPoolRefAddr.VA) {
		msg = L"Aob = CMS v86";
		return f.GetAddrInfo(*(DWORD *)(StringPoolRefAddr.RA + 0x06 + 0x03));
	}

	return ai;
}