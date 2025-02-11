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

bool Poly_Restore_call_ptr(Frost &f, int vm_section, std::vector<AddrInfoEx> &result) {
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

	return true;
}

AddrInfoEx Find__EH_prolog(Frost &f) {
	AddrInfoEx aix = { L"_EH_prolog" , L"6A FF 50 64 A1 00 00 00 00 50 8B 44 24 0C 64 89 25 00 00 00 00 89 6C 24 0C 8D 6C 24 0C 50 C3", L"KMS v2.95" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 64 53 56 33 F6 57 89");
	if (res.VA) {
		res = f.GetRefAddrRelative(res.VA + 0x05, 0x01);
		if (res.VA) {
			if (((BYTE *)f.GetRawAddress(res.VA))[0] != 0xE9) {
				aix.patch = L"";
			}
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find__memset(Frost &f) {
	AddrInfoEx aix = { L"_memset" , L"8B 54 24 0C 8B 4C 24 04 85 D2 74 47 33 C0 8A 44 24 08 57 8B F9 83 FA 04 72 2D F7 D9 83 E1 03 74 08 2B D1 88 07 47 49 75 FA 8B C8 C1 E0 08 03 C1 8B C8 C1 E0 10 03 C1 8B CA 83 E2 03 C1 E9 02 74 06 F3 AB 85 D2 74 06 88 07 47 4A 75 FA 8B 44 24 08 5F C3 8B 44 24 04 C3", L"KMS v2.95" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"56 57 6A 0C 8B F1 33 FF 57 56 C7 06 ?? ?? ?? ?? E8");
	if (res.VA) {
		res = f.GetRefAddrRelative(res.VA + 0x10, 0x01);
		if (res.VA) {
			if (((BYTE *)f.GetRawAddress(res.VA))[0] != 0xE9) {
				aix.patch = L"";
				return aix;
			}
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find__strlen(Frost &f) {
	AddrInfoEx aix = { L"_strlen" , L"8B 4C 24 04 F7 C1 03 00 00 00 74 14 8A 01 41 84 C0 74 40 F7 C1 03 00 00 00 75 F1 05 00 00 00 00 8B 01 BA FF FE FE 7E 03 D0 83 F0 FF 33 C2 83 C1 04 A9 00 01 01 81 74 E8 8B 41 FC 84 C0 74 32 84 E4 74 24 A9 00 00 FF 00 74 13 A9 00 00 00 FF 74 02 EB CD 8D 41 FF 8B 4C 24 04 2B C1 C3 8D 41 FE 8B 4C 24 04 2B C1 C3 8D 41 FD 8B 4C 24 04 2B C1 C3 8D 41 FC 8B 4C 24 04 2B C1 C3", L"KMS v2.95" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"83 7C 24 04 00 57 8B F9 75 07 E8 ?? ?? ?? ?? EB 37 56 8B 74 24 10 83 FE FF 75 0C FF 74 24 0C E8");
	if (res.VA) {
		res = f.GetRefAddrRelative(res.VA + 0x1F, 0x01);
		if (res.VA) {
			if (((BYTE *)f.GetRawAddress(res.VA))[0] != 0xE9) {
				aix.patch = L"";
				return aix;
			}
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find__wincmdln(Frost &f) {
	AddrInfoEx aix = { L"_wincmdln" , L"", L"KMS v2.95" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"FF 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 9C F6 45 D0 01 74 06 0F B7 45 D4 EB 03 6A 0A 58 50");
	if (!res.VA) {
		// call ptr is not restored
		res = f.AobScan(L"E8 ?? ?? ?? ?? 90 E8 ?? ?? ?? ?? 89 45 9C F6 45 D0 01 74 06 0F B7 45 D4 EB 03 6A 0A 58 50");
	}
	if (res.VA) {
		res = f.GetRefAddrRelative(res.VA + 0x06, 0x01);
		if (res.VA) {
			if (((BYTE *)f.GetRawAddress(res.VA))[0] != 0xE9) {
				aix.patch = L"";
				return aix;
			}
			// patch
			{
				ULONG_PTR addr___mbctype_initialized = 0;
				ULONG_PTR addr___initmbctable = 0;
				ULONG_PTR addr__acmdln = 0;
				ULONG_PTR addr__ismbblead = 0;

				addr___initmbctable = f.AobScan(L"83 3D ?? ?? ?? ?? 00 75 12 6A FD E8 ?? ?? ?? ?? 59 C7 05 ?? ?? ?? ?? 01 00 00 00 C3").VA;
				if (addr___initmbctable) {
					addr___mbctype_initialized = *(DWORD *)f.GetRawAddress(addr___initmbctable + 0x02);
				}

				AddrInfo ai__setargv_inside = f.AobScan(L"68 04 01 00 00 56 53 FF 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? 89");
				if (!ai__setargv_inside.VA) {
					// call ptr is not restored
					ai__setargv_inside = f.AobScan(L"68 04 01 00 00 56 53 E8 ?? ?? ?? ?? 90 A1 ?? ?? ?? ?? 89");
				}
				if (ai__setargv_inside.VA) {
					addr__acmdln = *(DWORD *)f.GetRawAddress(ai__setargv_inside.VA + 0x0E);
				}

				addr__ismbblead = f.AobScan(L"6A 04 6A 00 FF 74 24 0C E8 3C 00 00 00 83 C4 0C C3").VA;

				aix.patch = L"83 3D\r\n"; // db is not needed
				aix.patch += L"dd " + DWORDtoString((DWORD)addr___mbctype_initialized) +  L" // ___mbctype_initialized\r\n";
				aix.patch += L"db 00\r\n";
				aix.patch += L"db 75 05\r\n";
				aix.patch += L"call " + DWORDtoString((DWORD)addr___initmbctable) +  L" // ___initmbctable\r\n";
				aix.patch += L"db 56\r\n";
				aix.patch += L"db 8B 35\r\n";
				aix.patch += L"dd " + DWORDtoString((DWORD)addr__acmdln) + L" // __acmdln\r\n";
				aix.patch += L"db 8A 06 3C 22 75 25 8A 46 01 46 3C 22 74 15 84 C0 74 11 0F B6 C0 50\r\n";
				aix.patch += L"call " + DWORDtoString((DWORD)addr__ismbblead) + L" // __ismbblead\r\n";
				aix.patch += L"db 85 C0 59 74 E6 46 EB E3 80 3E 22 75 0D 46 EB 0A 3C 20 76 06 46 80 3E 20 77 FA 8A 06 84 C0 74 04 3C 20 76 E9 8B C6 5E C3";
			}
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find__setenvp(Frost &f) {
	AddrInfoEx aix = { L"_setenvp" , L"", L"KMS v2.95" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	res = f.AobScan(L"A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89");
	if (res.VA) {
		ULONG_PTR addr___aenvptr = *(DWORD *)(BYTE *)f.GetRawAddress(res.VA + 0x0B);

		res = f.GetRefAddrRelative(res.VA + 0x14, 0x01);
		if (res.VA) {
			if (((BYTE *)f.GetRawAddress(res.VA))[0] != 0xE9) {
				aix.patch = L"";
				return aix;
			}
			// patch
			{
				ULONG_PTR addr_temp = 0;
				ULONG_PTR addr___mbctype_initialized = 0;
				ULONG_PTR addr___initmbctable = 0;
				ULONG_PTR addr__strlen = 0;
				ULONG_PTR addr__malloc = 0;
				ULONG_PTR addr__getenv = 0;
				ULONG_PTR addr___env_initialized = 0;
				ULONG_PTR addr__environ = 0;
				ULONG_PTR addr__amsg_exit = 0;
				ULONG_PTR addr__free = 0;
				ULONG_PTR addr__strcpy = 0;

				addr___initmbctable = f.AobScan(L"83 3D ?? ?? ?? ?? 00 75 12 6A FD E8 ?? ?? ?? ?? 59 C7 05 ?? ?? ?? ?? 01 00 00 00 C3").VA;
				if (addr___initmbctable) {
					addr___mbctype_initialized = *(DWORD *)f.GetRawAddress(addr___initmbctable + 0x02);
				}
				addr_temp = f.AobScan(L"83 7C 24 04 00 57 8B F9 75 07 E8 ?? ?? ?? ?? EB 37 56 8B 74 24 10 83 FE FF 75 0C FF 74 24 0C E8").VA;
				if (addr_temp) {
					addr__strlen = f.GetRefAddrRelative(addr_temp + 0x1F, 0x01).VA;
				}
				addr__malloc = f.AobScan(L"FF 35 ?? ?? ?? ?? FF 74 24 08 E8 ?? ?? ?? ?? 59 59 C3").VA;
				addr__getenv = f.AobScan(L"83 3D ?? ?? ?? ?? 00 53 56 8B 35 ?? ?? ?? ?? 57 74 ?? 85 F6 75").VA;
				if (addr__getenv) {
					addr___env_initialized = *(DWORD *)f.GetRawAddress(addr__getenv + 0x02);
					addr__environ = *(DWORD *)f.GetRawAddress(addr__getenv + 0x0B);
				}
				addr__amsg_exit = f.AobScan(L"83 3D ?? ?? ?? ?? 01 75 05 E8 ?? ?? ?? ?? FF 74 24 04 E8 ?? ?? ?? ?? 68 FF 00 00 00 FF 15").VA;
				addr__free = f.AobScan(L"55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 18 53 56 57 8B 75 08 85 F6 0F 84 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 F8 03 75 ?? 6A 09 E8").VA;
				addr__strcpy = f.AobScan(L"57 8B 7C 24 08 EB 6A 8D A4 24 00 00 00 00 8B FF 8B 4C 24 04 57 F7 C1 03 00 00 00 74").VA;

				aix.patch += L"53 33 DB\r\n";
				aix.patch += L"db 39 1D\r\n";
				aix.patch += L"dd " + DWORDtoString((DWORD)addr___mbctype_initialized) + L" // ___mbctype_initialized\r\n";
				aix.patch += L"db 56 57 75 05\r\n";
				aix.patch += L"call " + DWORDtoString((DWORD)addr___initmbctable) + L" // ___initmbctable\r\n";
				aix.patch += L"db 8B 35\r\n";
				aix.patch += L"dd " + DWORDtoString((DWORD)addr___aenvptr) + L" // __aenvptr\r\n";
				aix.patch += L"db 33 FF 8A 06 3A C3 74 12 3C 3D 74 01 47 56\r\n";
				aix.patch += L"call " + DWORDtoString((DWORD)addr__strlen) + L" // _strlen\r\n";
				aix.patch += L"db 59 8D 74 06 01 EB E8 8D 04 BD 04 00 00 00 50\r\n";
				aix.patch += L"call " + DWORDtoString((DWORD)addr__malloc) + L" // _malloc\r\n";
				aix.patch += L"db 8B F0 59 3B F3\r\n";
				aix.patch += L"db 89 35\r\n";
				aix.patch += L"dd " + DWORDtoString((DWORD)addr__environ) + L" // _environ\r\n";
				aix.patch += L"db 75 08 6A 09\r\n";
				aix.patch += L"call " + DWORDtoString((DWORD)addr__amsg_exit) + L" // _amsg_exit\r\n";
				aix.patch += L"db 59\r\n";
				aix.patch += L"db 8B 3D\r\n";
				aix.patch += L"dd " + DWORDtoString((DWORD)addr___aenvptr) + L" // __aenvptr\r\n";
				aix.patch += L"db 38 1F 74 39 55 57\r\n";
				aix.patch += L"call " + DWORDtoString((DWORD)addr__strlen) + L" // _strlen\r\n";
				aix.patch += L"db 8B E8 59 45 80 3F 3D 74 22 55\r\n";
				aix.patch += L"call " + DWORDtoString((DWORD)addr__malloc) + L" // _malloc\r\n";
				aix.patch += L"db 3B C3 59 89 06 75 08 6A 09\r\n";
				aix.patch += L"call " + DWORDtoString((DWORD)addr__amsg_exit) + L" // _amsg_exit\r\n";
				aix.patch += L"db 59 57 FF 36\r\n";
				aix.patch += L"call " + DWORDtoString((DWORD)addr__strcpy) + L" // _strcpy\r\n";
				aix.patch += L"db 59 83 C6 04 59 03 FD 38 1F 75 C9 5D\r\n";
				aix.patch += L"db FF 35\r\n";
				aix.patch += L"dd " + DWORDtoString((DWORD)addr___aenvptr) + L" // __aenvptr\r\n";
				aix.patch += L"call " + DWORDtoString((DWORD)addr__free) + L" // _free\r\n";
				aix.patch += L"db 59\r\n";
				aix.patch += L"db 89 1D\r\n";
				aix.patch += L"dd " + DWORDtoString((DWORD)addr___aenvptr) + L" // __aenvptr\r\n";
				aix.patch += L"db 89 1E 5F 5E\r\n";
				aix.patch += L"db C7 05\r\n";
				aix.patch += L"dd " + DWORDtoString((DWORD)addr___env_initialized) + L" // __env_initialized\r\n";
				aix.patch += L"db 01 00 00 00 5B C3\r\n";
			}
			return aix;
		}
	}

	return aix;
}

AddrInfoEx Find__memset_2008(Frost &f) {
	AddrInfoEx aix = { L"_memset" , L"", L"KMS v2.114" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	// caller
	res = f.AobScan(L"E8 ?? ?? ?? ?? 0F B7 C3 83 C0 ?? 83 C4 0C 83 F8 ?? 0F 87 ?? ?? ?? ?? 0F B6 8? ?? ?? ?? ?? FF 24");
	if (!res.VA) {
		return aix;
	}
	// get call addr
	res = f.GetRefAddrRelative(res.VA, 0x01);
	if (!res.VA) {
		return aix;
	}
	// check asprotect junk code
	if (((BYTE *)f.GetRawAddress(res.VA))[0] != 0xE9) {
		aix.patch = L"";
		return aix;
	}
	ULONG_PTR addr_temp = 0;
	ULONG_PTR addr___sse2_available = 0;
	ULONG_PTR addr__VEC_memzero = 0;

	addr_temp = f.AobScan(L"83 3D ?? ?? ?? ?? 00 74 16 57 56 83 E7 0F 83 E6 0F 3B FE 5E 5F 75 08 5E 5F 5D E9").VA;
	if (addr_temp) {
		addr___sse2_available = *(DWORD *)f.GetRawAddress(addr_temp + 0x02);
	}

	// fastzero_I+57
	addr_temp = f.AobScan(L"55 8B EC 83 EC 04 89 7D FC 8B 7D 08 8B 4D 0C C1 E9 07 66 0F EF C0 EB 08 8D A4 24 00 00 00 00 90 66 0F 7F 07 66 0F 7F 47 10 66 0F 7F 47 20 66 0F 7F 47 30 66 0F 7F 47 40 66 0F 7F 47 50 66 0F 7F 47 60 66 0F 7F 47 70 8D BF 80 00 00 00 49 75 D0 8B 7D FC 8B E5 5D C3").VA;
	if (addr_temp) {
		addr__VEC_memzero = f.GetAddrInfo(addr_temp + 0x57).VA;
	}

	// patch
	aix.patch = L"8B 54 24 0C 8B 4C 24 04 85 D2 74 69 33 C0 8A 44 24 08 84 C0 75 16 81 FA 00 01 00 00 72 0E\r\n";
	aix.patch += L"db 83 3D\r\n";
	aix.patch += L"dd " + DWORDtoString((DWORD)addr___sse2_available) + L" // __sse2_available\r\n";
	aix.patch += L"db 00\r\n";
	aix.patch += L"db 74 05\r\n";
	aix.patch += L"jmp " + DWORDtoString((DWORD)addr__VEC_memzero) + L" // _VEC_memzero\r\n";
	aix.patch += L"db 57 8B F9 83 FA 04 72 31 F7 D9 83 E1 03 74 0C 2B D1 88 07 83 C7 01 83 E9 01 75 F6 8B C8 C1 E0 08 03 C1 8B C8 C1 E0 10 03 C1 8B CA 83 E2 03 C1 E9 02 74 06 F3 AB 85 D2 74 0A 88 07 83 C7 01 83 EA 01 75 F6 8B 44 24 08 5F C3 8B 44 24 04 C3\r\n";

	return aix;
}

AddrInfoEx Find__VEC_memzero_2008(Frost &f) {
	AddrInfoEx aix = { L"_VEC_memzero" , L"", L"KMS v2.114" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	// fastzero_I
	res = f.AobScan(L"55 8B EC 83 EC 04 89 7D FC 8B 7D 08 8B 4D 0C C1 E9 07 66 0F EF C0 EB 08 8D A4 24 00 00 00 00 90 66 0F 7F 07 66 0F 7F 47 10 66 0F 7F 47 20 66 0F 7F 47 30 66 0F 7F 47 40 66 0F 7F 47 50 66 0F 7F 47 60 66 0F 7F 47 70 8D BF 80 00 00 00 49 75 D0 8B 7D FC 8B E5 5D C3");
	if (!res.VA) {
		return aix;
	}
	res = f.GetAddrInfo(res.VA + 0x57); // fixed offset
	if (!res.VA) {
		return aix;
	}
	// check asprotect junk code
	if (((BYTE *)f.GetRawAddress(res.VA))[0] != 0xE9) {
		aix.patch = L"";
		return aix;
	}

	// this includes some call opcodes, but relative addr is always same
	aix.patch = L"55 8B EC 83 EC 10 89 7D FC 8B 45 08 99 8B F8 33 FA 2B FA 83 E7 0F 33 FA 2B FA 85 FF 75 3C 8B 4D 10 8B D1 83 E2 7F 89 55 F4 3B CA 74 12 2B CA 51 50 E8 73 FF FF FF 83 C4 08 8B 45 08 8B 55 F4 85 D2 74 45 03 45 10 2B C2 89 45 F8 33 C0 8B 7D F8 8B 4D F4 F3 AA 8B 45 08 EB 2E F7 DF 83 C7 10 89 7D F0 33 C0 8B 7D 08 8B 4D F0 F3 AA 8B 45 F0 8B 4D 08 8B 55 10 03 C8 2B D0 52 6A 00 51 E8 7E FF FF FF 83 C4 0C 8B 45 08 8B 7D FC 8B E5 5D C3";
	return aix;
}

AddrInfoEx Find__wincmdln_2008(Frost &f) {
	AddrInfoEx aix = { L"_wincmdln" , L"", L"KMS v2.114" };
	std::wstring &mode = aix.mode;
	AddrInfo &res = aix.info;

	// caller
	res = f.AobScan(L"E8 ?? ?? ?? ?? 84 5D ?? 74 06 0F B7 4D ?? EB 03 6A 0A 59 51 50 56 68 00 00 40 00 E8");
	if (!res.VA) {
		return aix;
	}
	// get call addr
	res = f.GetRefAddrRelative(res.VA, 0x01);
	if (!res.VA) {
		return aix;
	}
	// check asprotect junk code
	if (((BYTE *)f.GetRawAddress(res.VA))[0] != 0xE9) {
		aix.patch = L"";
		return aix;
	}
	
	ULONG_PTR addr_temp = 0;
	ULONG_PTR addr___mbctype_initialized = 0;
	ULONG_PTR addr___initmbctable = 0;
	ULONG_PTR addr__acmdln = 0;
	ULONG_PTR addr_sStrDefault = 0;
	ULONG_PTR addr__ismbblead = 0;

	addr___initmbctable = f.AobScan(L"83 3D ?? ?? ?? ?? 00 75 12 6A FD E8 ?? ?? ?? ?? 59 C7 05 ?? ?? ?? ?? 01 00 00 00 33 C0 C3").VA;
	if (addr___initmbctable) {
		addr___mbctype_initialized = *(DWORD *)f.GetRawAddress(addr___initmbctable + 0x02);
	}
	addr_temp = f.AobScan(L"FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8").VA;
	if (addr_temp) {
		addr__acmdln = *(DWORD *)f.GetRawAddress(addr_temp + 0x07);
	}
	addr_temp = f.AobScan(L"FF 15 ?? ?? ?? ?? 3D B5 03 00 00 74 ?? E8 ?? ?? ?? ?? 51 8B CC 89 65 ?? 6A FF 68").VA;
	if (addr_temp) {
		addr_sStrDefault = *(DWORD *)f.GetRawAddress(addr_temp + 0x1B);
	}
	addr__ismbblead = f.AobScan(L"8B FF 55 8B EC 6A 04 6A 00 FF 75 08 6A 00 E8 ?? ?? ?? ?? 83 C4 10 5D C3").VA;
	// patch
	aix.patch = L"8B FF 56 57 33 FF\r\n";
	aix.patch += L"db 39 3D\r\n";
	aix.patch += L"dd " + DWORDtoString((DWORD)addr___mbctype_initialized) + L" // __mbctype_initialized\r\n";
	aix.patch += L"db 75 05\r\n";
	aix.patch += L"call " + DWORDtoString((DWORD)addr___initmbctable) + L" // __initmbctable\r\n";
	aix.patch += L"db 8B 35\r\n";
	aix.patch += L"dd " + DWORDtoString((DWORD)addr__acmdln) + L" // addr__acmdln\r\n";
	aix.patch += L"db 85 F6 75 05\r\n";
	aix.patch += L"db BE\r\n";
	aix.patch += L"dd " + DWORDtoString((DWORD)addr_sStrDefault) + L" // sStrDefault\r\n";
	aix.patch += L"db 8A 06 3C 20 77 08 84 C0 74 2E 85 FF 74 24 3C 22 75 09 33 C9 85 FF 0F 94 C1 8B F9 0F B6 C0 50\r\n";
	aix.patch += L"call " + DWORDtoString((DWORD)addr__ismbblead) + L" //_ismbblead\r\n";
	aix.patch += L"db 59 85 C0 74 01 46 46 EB D3 3C 20 77 07 46 8A 06 84 C0 75 F5 5F 8B C6 5E C3\r\n";

	return aix;
}

// please compare KMS pre-BB (VS2006) and JMS v186, this is written by checking JMS memory.
bool Poly_Restore_function_VS_2006(Frost &f, int vm_section, std::vector<AddrInfoEx> &result) {
	bool is_faield = false;
	ADDSCANRESULT(_EH_prolog);
	CheckScanState(is_faield);
	ADDSCANRESULT(_memset);
	CheckScanState(is_faield);
	ADDSCANRESULT(_strlen);
	CheckScanState(is_faield);
	ADDSCANRESULT(_wincmdln);
	CheckScanState(is_faield);
	ADDSCANRESULT(_setenvp);
	CheckScanState(is_faield);
	return is_faield ? false : true;
}

// please compare KMS post-BB (VS2008) and JMS v188, this is written by checking JMS memory.
bool Poly_Restore_function_VS_2008(Frost &f, int vm_section, std::vector<AddrInfoEx> &result) {
	ADDSCANRESULT(_memset_2008);
	ADDSCANRESULT(_VEC_memzero_2008);
	ADDSCANRESULT(_wincmdln_2008);
	return true;
}


// ASPprotect
std::vector<AddrInfoEx> Scanner_ASProtect(Frost &f, int vm_section) {
	std::vector<AddrInfoEx> result;
	g_vm_section_aspr = vm_section;
	Poly_Restore_call_ptr(f, vm_section, result);
	// need to patch call ptr before you try this.
	if (!Poly_Restore_function_VS_2006(f, vm_section, result)) {
		Poly_Restore_function_VS_2008(f, vm_section, result);
	}
	return result;
}
