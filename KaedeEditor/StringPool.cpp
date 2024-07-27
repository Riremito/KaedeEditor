#include"StringPool.h"

// public
StringPool::StringPool(UINT cp, BYTE *xor_key, size_t size) {
	codepage = cp;
	for (size_t i = 0; i < size; i++) {
		key.push_back(xor_key[i]);
	}
}

std::vector<BYTE> StringPool::Decode(StringPoolData *spd) {
	std::vector<BYTE> xor_key = rotatel(spd);
	// not null terminating
	std::vector<BYTE> text;

	for (size_t i = 0; spd->data[i]; i++) {
		BYTE chr = (spd->data[i] != xor_key[i % xor_key.size()]) ? (spd->data[i] ^ xor_key[i % xor_key.size()]) : spd->data[i];
		text.push_back(chr);
	}

	return text;
}

std::wstring StringPool::DecodeWStr(StringPoolData *spd) {
	std::wstring wtext;
	std::vector<BYTE> data = Decode(spd);
	std::vector<BYTE> text;
	for (auto &v : data) {
		switch (v) {
		case '\r': {
			text.push_back('\\');
			text.push_back('r');
			break;
		}
		case '\n': {
			text.push_back('\\');
			text.push_back('n');
			break;
		}
		case '\t': {
			text.push_back('\\');
			text.push_back('t');
			break;
		}
		default: {
			text.push_back(v);
			break;
		}
		}
	}
	text.push_back(L'\0');
	ToWStr(text, wtext);
	return wtext;
}


// private
std::vector<BYTE> StringPool::rotatel(StringPoolData *spd) {
	// must be set original xor key as default
	std::vector<BYTE> xor_key = key;

	// rotate
	if (((spd->shift & 0x7F)>> 3)) {
		BYTE shift = ((spd->shift & 0x7F) >> 3) % xor_key.size();
		if (shift) {
			for (size_t i = 0; i < xor_key.size(); i++) {
				xor_key[i] = key[(i + shift) % xor_key.size()];
			}
		}
	}

	// generate key
	if ((spd->shift & 0x7F) & 7) {
		BYTE shift = (spd->shift & 0x7F) & 7;
		if (shift) {
			BYTE bit = (BYTE)(xor_key[0] >> (8 - shift));
			for (size_t i = 0; i < xor_key.size(); i++) {
				BYTE left = 0;
				if (i != (xor_key.size() - 1)) {
					left = (BYTE)(xor_key[i + 1] >> (8 - shift));
				}
				BYTE right = (BYTE)(xor_key[i] << shift);
				xor_key[i] = left | right;
			}
			xor_key[xor_key.size() - 1] |= bit;
		}
	}

	return xor_key;
}

bool StringPool::ToWStr(std::vector<BYTE> &text, std::wstring &wtext) {
	// get size
	int size = MultiByteToWideChar(codepage, 0, (char *)&text[0], -1, 0, 0);
	if (!size) {
		wtext = L"size err";
		return false;
	}

	// to utf16
	std::vector<BYTE> wb((size + 1) * sizeof(WORD));
	if (!MultiByteToWideChar(codepage, 0, (char *)&text[0], -1, (WCHAR *)&wb[0], size)) {
		wtext = L"convert err";
		return false;
	}

	wtext = std::wstring((WCHAR *)&wb[0]);
	return true;
}