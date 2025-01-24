#include"AobScanner.h"

int g_vm_section = 3;
int g_vm_section64 = 11;

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
		ULONG_PTR uRawAddr = f.GetRawAddress(uResultAddr);

		if (*(BYTE *)(uRawAddr + 0x02) == 0xE9 && *(BYTE *)(uRawAddr + 0x07) == 0xCC) {
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

std::vector<AddrInfoEx> Scanner_Themida_VMProtect(Frost &f, int vm_section) {
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

bool VM_Enter_Themida64(Frost &f, ULONG_PTR uResultAddr) {
	AddrInfo ai = f.GetRefAddrRelative(uResultAddr, 0x01);
	if (ai.VA == 0) {
		return false;
	}

	if (f.GetSectionNumber(ai.VA) == g_vm_section64) {
		ULONG_PTR uRawAddr = f.GetRawAddress(uResultAddr);
		if (*(BYTE *)(uRawAddr + 0x05) != 0x50) {
			return false;
		}

		return true;
	}

	return false;
}

std::vector<AddrInfoEx> Scanner_Themida_VMProtect64(Frost &f, int vm_section64) {
	std::vector<AddrInfoEx> result;

	AddrInfoEx aix = { L"VM_ENTER", L"" , L"Themida64" };
	AddrInfo &res = aix.info;

	size_t index = 0;
	g_vm_section64 = vm_section64;
	for (auto &v : f.AobScanAll(L"E9", VM_Enter_Themida64)) {
		aix.tag = L"VM_ENTER_" + std::to_wstring(index++);
		res = v;
		result.push_back(aix);
	}

	return result;
}
