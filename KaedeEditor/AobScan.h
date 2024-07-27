#ifndef __AOBSCAN_H__
#define __AOBSCAN_H__

#include<Windows.h>
#include<string>
#include<vector>

class AobScan {
private:
	bool init;
	std::vector<unsigned char> array_of_bytes;
	std::vector<unsigned char> mask;

	bool CreateAob(std::wstring wAob);

public:
	AobScan(std::wstring wAob);
#ifndef _WIN64
	bool Compare(unsigned long int uAddress);
#else
	bool Compare(unsigned __int64 uAddress);
#endif
	size_t size();
};

#endif