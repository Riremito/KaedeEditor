#include"AobScanner.h"


int g_vm_section_aspr = 6;

bool Poly_check(Frost &f, ULONG_PTR uResultAddr) {
	AddrInfo ai = f.GetRefAddrRelative(uResultAddr, 0x01);
	if (ai.VA == 0) {
		return false;
	}

	if (f.GetSectionNumber(ai.VA) == g_vm_section_aspr) {
		return true;
	}
	return false;
}

// ASPprotect
std::vector<AddrInfoEx> Scanner_ASProtect(Frost &f, int vm_section) {
	std::vector<AddrInfoEx> result;

	AddrInfoEx aix = { L"PolyCall", L"" , L"ASProtect" };
	AddrInfo &res = aix.info;

	size_t index = 0;
	//g_vm_section_aspr = vm_section;
	for (auto &v : f.AobScanAll(L"E8 ?? ?? ?? ?? 90", Poly_check)) {
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
