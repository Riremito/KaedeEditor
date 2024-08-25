#include"KaedeEditor.h"

Frost *frost_dropped = NULL;
int frost_ref_count = 0;

// close previous opened file
bool Dropped_Close() {
	if (frost_ref_count != 0) {
		return false;
	}

	if (frost_dropped) {
		delete frost_dropped;
		frost_dropped = NULL;
	}

	return true;
}

// open new file
bool Dropped_Open(const WCHAR *wPath) {
	if (frost_dropped) {
		return false;
	}

	frost_dropped = new Frost(wPath);
	if (!frost_dropped) {
		return false;
	}

	return true;
}

// parse PE file
bool Dropped_Parse() {
	if (!frost_dropped) {
		return false;
	}

	if (!frost_dropped->Parse()) {
		Dropped_Close();
		return false;
	}

	return true;
}

// thread task checks
void UnlockButton(Alice &a, int nIDDlgItem) {
	frost_ref_count--;
	a.ChangeState(nIDDlgItem, TRUE);
}

bool AobScanThread(Alice &a) {
	a.ListView_Clear(LISTVIEW_AOBSCAN_RESULT);
	a.SetText(TEXTAREA_INFO, L"");

	Frost &f = *frost_dropped;

	INFO_ADD(L"Loading...");

	std::vector<std::wstring> vAAScript;
	std::vector<std::wstring> vIDCScript;
	std::vector<std::wstring> vInfo;

	vAAScript.push_back(L"[Enable]");
	for (auto &v : f.Isx64() ? AobScannerMain64(f) : AobScannerMain(f)) {
		std::wstring wVA = v.info.VA ? (f.Isx64() ? QWORDtoString(v.info.VA) : DWORDtoString((DWORD)v.info.VA)) : L"ERROR";
		a.ListView_AddItem(LISTVIEW_AOBSCAN_RESULT, LVA_VA, wVA);
		a.ListView_AddItem(LISTVIEW_AOBSCAN_RESULT, LVA_NAME_TAG, v.tag);
		a.ListView_AddItem(LISTVIEW_AOBSCAN_RESULT, LVA_MODE, v.mode);
		a.ListView_AddItem(LISTVIEW_AOBSCAN_RESULT, LVA_PATCH, v.info.VA ? v.patch : L"ERROR");
		if (v.info.VA) {
			if (v.patch.length()) {
				// AA Script (CE)
				vAAScript.push_back(L"// " + v.tag);
				vAAScript.push_back(wVA + L":");
				if (memcmp(v.patch.c_str(), L"jmp ", 8) == 0) {
					vAAScript.push_back(v.patch);
				}
				else {
					vAAScript.push_back(L"db " + v.patch);
				}
				vAAScript.push_back(L""); // LF
				continue;
			}
			else {
				// Info (IDA)
				if (v.tag.length() && v.tag.at(0) == L'?') {
					vIDCScript.push_back(L"set_name(0x" + wVA + L", \"" + v.tag + L"\");");
					continue;
				}
			}
		}
		vInfo.push_back(wVA + L" = " + v.tag);
	}
	vAAScript.push_back(L"[Disable]");
	INFO_ADD(L"// AA Script (CE)");
	for (auto &v : vAAScript) {
		INFO_ADD(v);
	}
	INFO_ADD(L"");
	INFO_ADD(L"// IDC Script (IDA)");
	for (auto &v : vIDCScript) {
		INFO_ADD(v);
	}
	INFO_ADD(L"");
	INFO_ADD(L"// Info");
	for (auto &v : vInfo) {
		INFO_ADD(v);
	}
	INFO_ADD(L"");
	INFO_ADD(L"OK!");

	UnlockButton(a, BUTTON_AOBSCAN);
	return true;
}

bool VMScanThread(Alice &a) {
	a.ListView_Clear(LISTVIEW_AOBSCAN_RESULT);
	a.SetText(TEXTAREA_INFO, L"");

	Frost &f = *frost_dropped;

	INFO_ADD(L"Loading...");

	int vm_section = _wtoi(a.GetText(EDIT_VM_SECTION).c_str()); // x86 = 3, x64 = 11
	for (auto &v : f.Isx64() ? VMScanner64(f, vm_section) : VMScanner(f, vm_section)) {
		std::wstring wVA = v.info.VA ? (f.Isx64() ? QWORDtoString(v.info.VA) : DWORDtoString((DWORD)v.info.VA)) : L"ERROR";
		a.ListView_AddItem(LISTVIEW_AOBSCAN_RESULT, LVA_VA, wVA);
		a.ListView_AddItem(LISTVIEW_AOBSCAN_RESULT, LVA_NAME_TAG, v.tag);
		a.ListView_AddItem(LISTVIEW_AOBSCAN_RESULT, LVA_MODE, v.mode);
		a.ListView_AddItem(LISTVIEW_AOBSCAN_RESULT, LVA_PATCH, v.info.VA ? v.patch : L"ERROR");
	}

	INFO_ADD(L"OK!");
	UnlockButton(a, BUTTON_VM_SCAN);
	return true;
}


// thread
bool RunScanner(Alice &a, int nIDDlgItem) {
	LPTHREAD_START_ROUTINE thread_func = NULL;
	switch (nIDDlgItem) {
	case BUTTON_AOBSCAN: {
		thread_func = (decltype(thread_func))AobScanThread;
		break;
	}
	case BUTTON_VM_SCAN: {
		thread_func = (decltype(thread_func))VMScanThread;
		break;
	}
	default: {
		break;
	}
	}

	if (!thread_func) {
		return false;
	}

	// scan thread
	frost_ref_count++;
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)thread_func, (LPVOID)&a, NULL, NULL);
	if (hThread) {
		CloseHandle(hThread);
	}
	return true;
}


// Main Window
bool OnCreate(Alice &a) {
	a.StaticText(STATIC_PATH, L"File Path :", 10, 3);
	a.EditBox(EDIT_PATH, 80, 3, L"Please Drop File", 500);
	a.ReadOnly(EDIT_PATH);
	a.Button(BUTTON_AOBSCAN, L"AobScan", 590, 3, 100);
	a.ListView(LISTVIEW_AOBSCAN_RESULT, 3, 30, (VIEWER_WIDTH - 6), 300);
	a.ListView_AddHeader(LISTVIEW_AOBSCAN_RESULT, L"VA", 120);
	a.ListView_AddHeader(LISTVIEW_AOBSCAN_RESULT, L"NameTag", 300);
	a.ListView_AddHeader(LISTVIEW_AOBSCAN_RESULT, L"Mode", 100);
	a.ListView_AddHeader(LISTVIEW_AOBSCAN_RESULT, L"Patch", 200);
	a.EditBox(EDIT_SELECTED, 3, 340, L"", (VIEWER_WIDTH - 6));
	a.TextArea(TEXTAREA_INFO, 3, 360, (VIEWER_WIDTH - 6), 200);
	a.ReadOnly(TEXTAREA_INFO);
	a.Button(BUTTON_VM_SCAN, L"VM Scan", 650, 570, 100);
	a.StaticText(STATIC_VM_SECTION, L"VM Section : ", 500, 570);
	a.EditBox(EDIT_VM_SECTION, 580, 570, L"3", 60);
	return true;
}

// Button
bool OnCommand(Alice &a, int nIDDlgItem) {
	switch (nIDDlgItem) {
	case BUTTON_AOBSCAN:
	case BUTTON_VM_SCAN:
	{
		// file is not opened.
		if (!frost_dropped) {
			return false;
		}
		a.ChangeState(nIDDlgItem, FALSE);
		RunScanner(a, nIDDlgItem);
		return true;
	}
	default: {
		break;
	}
	}
	return true;
}

// ListView Select -> Copy selected data
bool OnNotify(Alice &a, int nIDDlgItem) {
	if (nIDDlgItem == LISTVIEW_AOBSCAN_RESULT) {
		std::wstring text_va;
		std::wstring text_name_tag;
		a.ListView_Copy(LISTVIEW_AOBSCAN_RESULT, LVA_VA, text_va, false);
		a.ListView_Copy(LISTVIEW_AOBSCAN_RESULT, LVA_NAME_TAG, text_name_tag, true, 4096);
		a.SetText(EDIT_SELECTED, text_va + L" | " + text_name_tag);
		return true;
	}
	return true;
}

// Drop -> Open
bool OnDropFile(Alice &a, wchar_t *drop) {
	INFO_CLEAR();
	if (!Dropped_Close()) {
		INFO_ADD(L"Error! Previous task is still running.");
		return false;
	}

	a.SetText(EDIT_PATH, drop);
	INFO_ADD(drop);
	Dropped_Open(drop);

	if (!Dropped_Parse()) {
		INFO_ADD(L"Error! Unable to open PE file.");
		return false;
	}

	Frost &f = *frost_dropped;
	f.Isx64() ? a.SetText(EDIT_VM_SECTION, L"11") : a.SetText(EDIT_VM_SECTION, L"3");
	return true;
}


int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
	Alice a(L"KaedeEditorClass", L"Kaede Editor", VIEWER_WIDTH, VIEWER_HEIGHT, hInstance);
	a.SetOnCreate(OnCreate);
	a.SetOnCommand(OnCommand);
	a.SetOnNotify(OnNotify);
	a.SetOnDropFile(OnDropFile);
	a.Run();
	a.Wait();
	Dropped_Close();
	return 0;
}
