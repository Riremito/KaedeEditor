#ifndef __STRINGPOOL_H__
#define __STRINGPOOL_H__

#include<Windows.h>
#include<string>
#include<vector>

#pragma pack(1)
typedef struct {
	BYTE shift;
	BYTE data[1];
} StringPoolData;
#pragma pack()

class StringPool {
private:
	UINT codepage;
	std::vector<BYTE> key;
	std::vector<BYTE> rotatel(StringPoolData *spd);
	bool ToWStr(std::vector<BYTE> &text, std::wstring &wtext);
public:
	StringPool(UINT cp, BYTE *xor_key, size_t size);
	std::vector<BYTE> Decode(StringPoolData *spd);
	std::wstring DecodeWStr(StringPoolData *spd);
};

#endif