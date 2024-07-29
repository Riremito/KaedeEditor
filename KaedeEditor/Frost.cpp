#include"Frost.h"
#include"AobScan.h"

// public
Frost::Frost(const WCHAR *wPath) {
	input_file_path = wPath;
	input_file_handle = INVALID_HANDLE_VALUE;
	input_file_map = NULL;
	input_file_size = 0;
	input_file_size_high = 0;
	input_file_data = 0;
	ImageBase = 0;
	is_x64 = false;
}

Frost::~Frost() {
	if (input_file_data) {
		UnmapViewOfFile(input_file_data);
	}
	if (input_file_map) {
		CloseHandle(input_file_map);
	}
	if (input_file_handle != INVALID_HANDLE_VALUE) {
		CloseHandle(input_file_handle);
	}
}

bool Frost::Parse() {
	if (!Open()) {
		return false;
	}

	DWORD req_size = 0;
	ULONG_PTR base = (ULONG_PTR)input_file_data;

	req_size += sizeof(IMAGE_DOS_HEADER);
	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER *)base;
	if (input_file_size < req_size) {
		return false;
	}
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}
	// IMAGE_DOS_HEADER
	req_size = idh->e_lfanew + sizeof(DWORD); // checkplz
	IMAGE_NT_HEADERS *inh = (IMAGE_NT_HEADERS *)(base + idh->e_lfanew);
	if (input_file_size < req_size) {
		return false;
	}
	if (inh->Signature != IMAGE_NT_SIGNATURE) {
		return false;
	}
	req_size += sizeof(IMAGE_FILE_HEADER);
	if (input_file_size < req_size) {
		return false;
	}
	// x86
	if (inh->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		IMAGE_NT_HEADERS32 *inh32 = (IMAGE_NT_HEADERS32 *)inh;
		if (inh32->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32) - (sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES)) {
			return false;
		}
		req_size += inh32->FileHeader.SizeOfOptionalHeader;
		if (input_file_size < req_size) {
			return false;
		}
		IMAGE_OPTIONAL_HEADER32 *ioh32 = &inh32->OptionalHeader;
		if (ioh32->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			return false;
		}
		if (ioh32->NumberOfRvaAndSizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
			// not supported now
			return false;
		}
		req_size += sizeof(IMAGE_SECTION_HEADER) * inh32->FileHeader.NumberOfSections;
		IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER *)((ULONG_PTR)ioh32 + inh32->FileHeader.SizeOfOptionalHeader);
		if (input_file_size < req_size) {
			return false;
		}
		// fixed base addr
		ImageBase = ioh32->ImageBase;
		// section info
		for (WORD i = 0; i < inh32->FileHeader.NumberOfSections; i++) {
			image_section_headers.push_back(ish[i]);
		}
	}
	// x64
	else if (inh->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		is_x64 = true;
		IMAGE_NT_HEADERS64 *inh64 = (IMAGE_NT_HEADERS64 *)inh;
		// not coded yet
		if (inh64->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) - (sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES)) {
			return false;
		}
		req_size += inh64->FileHeader.SizeOfOptionalHeader;
		if (input_file_size < req_size) {
			return false;
		}
		IMAGE_OPTIONAL_HEADER64 *ioh64 = &inh64->OptionalHeader;
		if (ioh64->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			return false;
		}
		// IMAGE_SUBSYSTEM_WINDOWS_GUI or IMAGE_SUBSYSTEM_WINDOWS_CUI
		if (ioh64->NumberOfRvaAndSizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
			// not supported now
			return false;
		}
		// Section Header
		req_size += sizeof(IMAGE_SECTION_HEADER) * inh64->FileHeader.NumberOfSections;
		IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER *)((ULONG_PTR)ioh64 + inh64->FileHeader.SizeOfOptionalHeader);
		if (input_file_size < req_size) {
			return false;
		}
		// fixed base addr
		ImageBase = ioh64->ImageBase;
		// section info
		for (WORD i = 0; i < inh64->FileHeader.NumberOfSections; i++) {
			image_section_headers.push_back(ish[i]);
		}
	}
	else {
		return false;
	}

	return true;
}

bool Frost::Isx64() {
	return is_x64;
}

ULONG_PTR Frost::GetRawAddress(ULONG_PTR uVirtualAddress) {
	if (!ImageBase || !uVirtualAddress) {
		return 0;
	}

	for (size_t i = 0; image_section_headers.size(); i++) {
		ULONG_PTR section_start = ImageBase + image_section_headers[i].VirtualAddress;
		ULONG_PTR section_end = section_start + image_section_headers[i].Misc.VirtualSize;

		// convert
		if (section_start <= uVirtualAddress && uVirtualAddress <= section_end) {
			return uVirtualAddress - section_start + image_section_headers[i].PointerToRawData + (ULONG_PTR)input_file_data; // file offset
		}
	}
	return 0;
}

ULONG_PTR Frost::GetVirtualAddress(ULONG_PTR uRawAddress) {
	if (!ImageBase) {
		return 0;
	}

	for (size_t i = 0; image_section_headers.size(); i++) {
		ULONG_PTR section_start = (ULONG_PTR)input_file_data + image_section_headers[i].PointerToRawData;
		ULONG_PTR section_end = section_start + image_section_headers[i].SizeOfRawData;

		// convert
		if (section_start <= uRawAddress && uRawAddress <= section_end) {
			return ImageBase + image_section_headers[i].VirtualAddress + (uRawAddress - section_start); // VA
		}
	}
	return 0;
}


AddrInfo Frost::AobScan(std::wstring wAob, bool scan_all_section) {
	AddrInfo asr = { 0 };
	::AobScan aob(wAob);
	if (!ImageBase) {
		return asr;
	}

	size_t aob_size = aob.size();
	if (aob_size == 0) {
		return asr;
	}

	if (!image_section_headers.size()) {
		return asr;
	}

	for (auto &v : image_section_headers) {
		ULONG_PTR uStartAddr = (ULONG_PTR)input_file_data + v.PointerToRawData;
		ULONG_PTR uEndAddr = uStartAddr + v.SizeOfRawData - aob_size;

		for (ULONG_PTR uAddr = uStartAddr; uAddr < uEndAddr; uAddr++) {
			if (aob.Compare(uAddr)) {
				ULONG_PTR uVA = GetVirtualAddress(uAddr);
				asr.VA = uVA;
				asr._RVA = uVA - ImageBase;
				asr.RA = uAddr;
				asr._RRA = uAddr - (ULONG_PTR)input_file_data;
				return asr;
			}
		}

		if (!scan_all_section) {
			break;
		}
	}

	return asr;
}

std::vector<AddrInfo> Frost::AobScanFin(std::wstring wAob, bool scan_all_section) {
	std::vector<AddrInfo> asrs;
	::AobScan aob(wAob);
	if (!ImageBase) {
		return asrs;
	}

	size_t aob_size = aob.size();
	if (aob_size == 0) {
		return asrs;
	}

	if (!image_section_headers.size()) {
		return asrs;
	}

	for (auto &v : image_section_headers) {
		ULONG_PTR uStartAddr = (ULONG_PTR)input_file_data + v.PointerToRawData;
		ULONG_PTR uEndAddr = uStartAddr + v.SizeOfRawData - aob_size;

		for (ULONG_PTR uAddr = uStartAddr; uAddr < uEndAddr; uAddr++) {
			if (aob.Compare(uAddr)) {
				AddrInfo asr = { 0 };
				ULONG_PTR uVA = GetVirtualAddress(uAddr);
				asr.VA = uVA;
				asr._RVA = uVA - ImageBase;
				asr.RA = uAddr;
				asr._RRA = uAddr - (ULONG_PTR)input_file_data;
				asrs.push_back(asr);
			}
		}

		if (!scan_all_section) {
			break;
		}
	}

	return asrs;
}


bool Frost::MemoryCompare(ULONG_PTR uAddr, ULONG_PTR uMemory, size_t size) {
	for (size_t i = 0; i < size; i++) {
		if (((BYTE *)uAddr)[i] != ((BYTE *)uMemory)[i]) {
			return false;
		}
	}
	return true;
}

AddrInfo Frost::ScanString(std::wstring wString) {
	AddrInfo asr = { 0 };
	std::vector<BYTE> target;
	size_t target_size = (wString.length() + 1) * sizeof(WCHAR);
	target.resize(target_size);
	memcpy_s(&target[0], target_size, wString.c_str(), target_size);

	for (auto &v : image_section_headers) {
		ULONG_PTR uStartAddr = (ULONG_PTR)input_file_data + v.PointerToRawData;
		ULONG_PTR uEndAddr = uStartAddr + v.SizeOfRawData - target_size;

		for (ULONG_PTR uAddr = uStartAddr; uAddr < uEndAddr; uAddr++) {
			if (MemoryCompare(uAddr, (ULONG_PTR)&target[0], target_size)) {
				ULONG_PTR uVA = GetVirtualAddress(uAddr);
				asr.VA = uVA;
				asr._RVA = uVA - ImageBase;
				asr.RA = uAddr;
				asr._RRA = uAddr - (ULONG_PTR)input_file_data;
				return asr;
			}
		}
	}
	return asr;
}


AddrInfo Frost::ScanString(std::string sString) {
	AddrInfo asr = { 0 };
	std::vector<BYTE> target;
	size_t target_size = (sString.length() + 1) * sizeof(char);
	target.resize(target_size);
	memcpy_s(&target[0], target_size, sString.c_str(), target_size);

	for (auto &v : image_section_headers) {
		ULONG_PTR uStartAddr = (ULONG_PTR)input_file_data + v.PointerToRawData;
		ULONG_PTR uEndAddr = uStartAddr + v.SizeOfRawData - target_size;

		for (ULONG_PTR uAddr = uStartAddr; uAddr < uEndAddr; uAddr++) {
			if (MemoryCompare(uAddr, (ULONG_PTR)&target[0], target_size)) {
				ULONG_PTR uVA = GetVirtualAddress(uAddr);
				asr.VA = uVA;
				asr._RVA = uVA - ImageBase;
				asr.RA = uAddr;
				asr._RRA = uAddr - (ULONG_PTR)input_file_data;
				return asr;
			}
		}
	}
	return asr;
}

AddrInfo Frost::ScanValue(ULONG_PTR uValue) {
	AddrInfo asr = { 0 };
	size_t target_size = sizeof(ULONG_PTR);

	for (auto &v : image_section_headers) {
		ULONG_PTR uStartAddr = (ULONG_PTR)input_file_data + v.PointerToRawData;
		ULONG_PTR uEndAddr = uStartAddr + v.SizeOfRawData - target_size;

		for (ULONG_PTR uAddr = uStartAddr; uAddr < uEndAddr; uAddr++) {
			if (MemoryCompare(uAddr, (ULONG_PTR)&uValue, target_size)) {
				ULONG_PTR uVA = GetVirtualAddress(uAddr);
				asr.VA = uVA;
				asr._RVA = uVA - ImageBase;
				asr.RA = uAddr;
				asr._RRA = uAddr - (ULONG_PTR)input_file_data;
				return asr;
			}
		}
	}
	return asr;
}

AddrInfo Frost::GetAddrInfo(ULONG_PTR uVirtualAddress) {
	AddrInfo ai = { 0 };
	ai.VA = uVirtualAddress;
	ai._RVA = ai.VA - ImageBase;
	ai.RA = GetRawAddress(uVirtualAddress);
	ai._RRA = ai.RA - (ULONG_PTR)input_file_data;
	return ai;
}

AddrInfo Frost::GetRefAddrRelative(ULONG_PTR uVirtualAddress, size_t position) {
	AddrInfo ai = { 0 };

	ULONG_PTR raw_addr = GetRawAddress(uVirtualAddress);
	if (!raw_addr) {
		return ai;
	}

	ULONG_PTR ref_va = uVirtualAddress + (position + 0x04) + *(signed long int*)(raw_addr + position);
	ULONG_PTR ref_raw = GetRawAddress(ref_va);

	if (!ref_raw) {
		return ai;
	}

	ai.VA = ref_va;
	ai._RVA = ai.VA - ImageBase;
	ai.RA = ref_raw;
	ai._RRA = ai.RA - (ULONG_PTR)input_file_data;
	return ai;
}

// private
bool Frost::Open() {
	input_file_handle = CreateFileW(input_file_path.c_str(), GENERIC_READ, (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE), NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (input_file_handle == INVALID_HANDLE_VALUE) {
		return false;
	}

	input_file_size = GetFileSize(input_file_handle, &input_file_size_high);
	if (input_file_size_high || input_file_size < 2) {
		return false;
	}

	input_file_map = CreateFileMappingW(input_file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!input_file_map) {
		return false;
	}

	input_file_data = MapViewOfFile(input_file_map, FILE_MAP_READ, 0, 0, 0);
	if (!input_file_data) {
		return false;
	}

	return true;
}