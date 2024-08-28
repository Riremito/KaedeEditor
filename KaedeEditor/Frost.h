#ifndef __FROST_H__
#define __FROST_H__

#include<Windows.h>
#include<winternl.h>
#include<string>
#include<vector>

typedef struct {
	ULONG_PTR VA; // Virtual Address
	ULONG_PTR _RVA; // Virtual Address
	ULONG_PTR RA; // Raw Address (Opened File Offset)
	ULONG_PTR _RRA; // File Offset
} AddrInfo;

class Frost {
private:
	// input
	std::wstring input_file_path;
	HANDLE input_file_handle;
	HANDLE input_file_map;
	void *input_file_data;
	DWORD input_file_size;
	DWORD input_file_size_high;
	// reader
	ULONG_PTR ImageBase;
	std::vector<IMAGE_SECTION_HEADER> image_section_headers;
	bool is_x64;

	bool Open();
	bool MemoryCompare(ULONG_PTR uAddr, ULONG_PTR uMemory, size_t size);
public:
	Frost(const WCHAR *wPath);
	~Frost();
	bool Parse();
	bool Isx64();
	ULONG_PTR GetRawAddress(ULONG_PTR uVirtualAddress);
	ULONG_PTR GetVirtualAddress(ULONG_PTR uRawAddress);
	AddrInfo AobScan(std::wstring wAob, bool (*scan_func)(Frost &, ULONG_PTR) = NULL, bool scan_all_section = false);
	std::vector<AddrInfo> AobScanAll(std::wstring wAob, bool (*scan_func)(Frost &, ULONG_PTR) = NULL, bool scan_all_section = false);
	int GetSectionNumber(ULONG_PTR uVirtualAddress);
	AddrInfo ScanString(std::wstring wString);
	AddrInfo ScanString(std::string sString);
	AddrInfo ScanValue(ULONG_PTR uValue);
	AddrInfo GetAddrInfo(ULONG_PTR uVirtualAddress);
	AddrInfo GetRefAddrRelative(ULONG_PTR uVirtualAddress, size_t position);
};

#endif