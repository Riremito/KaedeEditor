#include"Simple.h"

// public
bool Alice::ListView_AddHeader(size_t nIDDlgItem, std::wstring wHeader, int Width) {
	if (!main_hwnd) {
		return false;
	}

	LVCOLUMNW col;
	memset(&col, 0, sizeof(col));
	col.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	col.fmt = LVCFMT_LEFT;
	col.iSubItem = (int)ListView_HeaderCount(nIDDlgItem);

	col.cx = Width;
	col.pszText = (WCHAR *)wHeader.c_str();
	SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, LVM_INSERTCOLUMNW, col.iSubItem, (LPARAM)&col);
	return true;
}

bool Alice::ListView_AddItem(size_t nIDDlgItem, int index, std::wstring wText) {
	if (!main_hwnd) {
		return false;
	}

	LVITEMW item = { 0 };
	item.mask = LVIF_TEXT;
	item.pszText = (WCHAR *)wText.c_str();
	item.iSubItem = index;

	LRESULT count = ListView_LineCount(nIDDlgItem);

	if (index) {
		count--;
	}

	item.iItem = (int)count;

	if (!index) {
		SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, LVM_INSERTITEM, 0, (LPARAM)&item);
	}
	else {
		SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, LVM_SETITEM, 0, (LPARAM)&item);
	}

	if (index == ListView_HeaderCount(nIDDlgItem) - 1) {
		ListView_AutoScroll(nIDDlgItem);
	}

	return true;
}

bool Alice::ListView_AddItemWOS(size_t nIDDlgItem, int index, std::wstring wText) {
	if (!main_hwnd) {
		return false;
	}

	LVITEMW item = { 0 };
	item.mask = LVIF_TEXT;
	item.pszText = (WCHAR *)wText.c_str();
	item.iSubItem = index;

	LRESULT count = ListView_LineCount(nIDDlgItem);

	if (index) {
		count--;
	}

	item.iItem = (int)count;

	if (!index) {
		SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, LVM_INSERTITEM, 0, (LPARAM)&item);
	}
	else {
		SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, LVM_SETITEM, 0, (LPARAM)&item);
	}
	return true;
}

bool Alice::ListView_UpdateItem(size_t nIDDlgItem, int index, int line, std::wstring wText) {
	if (!main_hwnd) {
		return false;
	}

	if (ListView_HeaderCount(nIDDlgItem) < index) {
		return false;
	}

	LRESULT max_count = ListView_LineCount(nIDDlgItem);
	if (max_count < line) {
		return false;
	}

	LVITEMW item = { 0 };
	item.mask = LVIF_TEXT;
	item.pszText = (WCHAR *)wText.c_str();
	item.iSubItem = index;
	item.iItem = line;

	SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, LVM_SETITEM, 0, (LPARAM)&item);
	return true;
}

bool Alice::ListView_Clear(size_t nIDDlgItem) {
	if (!main_hwnd) {
		return false;
	}
	SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, LVM_DELETEALLITEMS, 0, 0);
	ListView_SetPreviousSelected(nIDDlgItem, -1);
	return true;
}

bool Alice::ListView_Copy(size_t nIDDlgItem, int index, std::wstring &wText, bool block, size_t size) {
	if (!main_hwnd) {
		return false;
	}

	LRESULT res = SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, LVM_GETNEXTITEM, -1, MAKELPARAM(LVNI_SELECTED, 0));
	if (res == -1) {
		return false;
	}

	int previous_res = 0;
	if (!ListView_GetPreviousSelected(nIDDlgItem, previous_res)) {
		return false;
	}

	if (res == previous_res) {
		return false;
	}

	if (block) {
		ListView_SetPreviousSelected(nIDDlgItem, (int)res);
	}

	wText.clear();

	std::vector<wchar_t> temp_text(size);

	LVITEMW li;
	memset(&li, 0, sizeof(li));
	li.iSubItem = index;
	li.pszText = &temp_text[0];
	li.cchTextMax = (int)(temp_text.size() - 1);
	SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, LVM_GETITEMTEXT, res, (LPARAM)&li);

	wText = &temp_text[0];

	return true;
}

bool Alice::ListView_Find(size_t nIDDlgItem, int index, std::wstring &wText, int &line) {
	if (!main_hwnd) {
		return false;
	}

	if (ListView_HeaderCount(nIDDlgItem) < index) {
		return false;
	}

	LRESULT max_count = ListView_LineCount(nIDDlgItem);
	std::vector<wchar_t> temp_text(256);
	LVITEMW li;
	memset(&li, 0, sizeof(li));
	li.iSubItem = index;
	li.pszText = &temp_text[0];
	li.cchTextMax = (int)(temp_text.size() - 1);
	std::wstring wtemp_text;

	for (int i = 0; i < max_count; i++) {
		memset(&temp_text[0], 0, sizeof(wchar_t) * 256);
		SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, LVM_GETITEMTEXT, (WPARAM)i, (LPARAM)&li);
		wtemp_text = &temp_text[0];
		if (wText.compare(wtemp_text) == 0) {
			line = i;
			return true;
		}
	}
	return false;
}

// private
LRESULT Alice::ListView_HeaderCount(size_t nIDDlgItem) {
	if (!main_hwnd) {
		return 0;
	}

	HWND header_hwnd = (HWND)SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, LVM_GETHEADER, 0, 0);
	return SendMessageW(header_hwnd, HDM_GETITEMCOUNT, 0, 0);
}

LRESULT Alice::ListView_LineCount(size_t nIDDlgItem) {
	if (!main_hwnd) {
		return 0;
	}

	return SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, LVM_GETITEMCOUNT, 0, 0);
}


bool Alice::ListView_AutoScroll(size_t nIDDlgItem) {
	if (!main_hwnd) {
		return false;
	}

	LRESULT count = SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, LVM_GETITEMCOUNT, 0, 0);
	SendDlgItemMessageW(main_hwnd, (int)nIDDlgItem, LVM_ENSUREVISIBLE, (WPARAM)(count - 1), true);
	return true;
}

bool Alice::ListView_GetPreviousSelected(size_t nIDDlgItem, int &Selected) {
	for (size_t i = 0; i < listview_id_list.size(); i++) {
		if (listview_id_list[i] == nIDDlgItem) {
			Selected = listview_previous_selected[i];
			return true;
		}
	}

	return false;
}

bool Alice::ListView_SetPreviousSelected(size_t nIDDlgItem, int Selected) {
	for (size_t i = 0; i < listview_id_list.size(); i++) {
		if (listview_id_list[i] == nIDDlgItem) {
			listview_previous_selected[i] = Selected;
			return true;
		}
	}

	return false;
}