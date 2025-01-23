#include"KaedeEditor.h"

Alice *alice_global = NULL;
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
void UnlockButton(int nIDDlgItem) {
	Alice &a = *alice_global;
	frost_ref_count--;
	a.ChangeState(nIDDlgItem, TRUE);
}

// test
bool AobScanTestThread() {
	Frost &f = *frost_dropped;
	Alice &a = *alice_global;
	a.SetText(EDIT_AOB_SCAN_TEST_RESULT, L"Scanning...");

	ULONG_PTR res_addr = f.AobScan(a.GetText(EDIT_AOB_SCAN_TEST)).VA;
	if (res_addr) {
		a.SetText(EDIT_AOB_SCAN_TEST_RESULT, f.Isx64() ? QWORDtoString(res_addr) : DWORDtoString((DWORD)res_addr));
	}
	else {
		a.SetText(EDIT_AOB_SCAN_TEST_RESULT, L"ERROR");
	}

	UnlockButton(BUTTON_AOB_SCAN_TEST);
	return true;
}

// Scanner
bool RunAobScanner(std::vector<AddrInfoEx> &vAddrInfoEx) {
	Alice &a = *alice_global;
	Frost &f = *frost_dropped;

	std::vector<std::wstring> vAAScript;
	std::vector<std::wstring> vIDCScript;
	std::vector<std::wstring> vInfo;

	for (auto &v : vAddrInfoEx) {
		std::wstring wVA = v.info.VA ? (f.Isx64() ? QWORDtoString(v.info.VA) : DWORDtoString((DWORD)v.info.VA)) : L"ERROR";
		a.ListView_AddItem(LISTVIEW_AOB_SCAN_RESULT, LVA_VA, wVA);
		a.ListView_AddItem(LISTVIEW_AOB_SCAN_RESULT, LVA_NAME_TAG, v.tag);
		a.ListView_AddItem(LISTVIEW_AOB_SCAN_RESULT, LVA_MODE, v.mode);
		a.ListView_AddItem(LISTVIEW_AOB_SCAN_RESULT, LVA_PATCH, v.info.VA ? v.patch : L"ERROR");
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
				vAAScript.push_back(L"");
				continue;
			}
			else {
				// IDC Script (IDA)
				if (v.tag.length() && v.tag.at(0) == L'?') {
					vIDCScript.push_back(L"set_name(0x" + wVA + L", \"" + v.tag + L"\");");
					continue;
				}
			}
		}
		vInfo.push_back(wVA + L" // " + v.tag);
	}

	INFO_ADD(L"// Kaede Editor");
	INFO_ADD(L"// File = " + a.GetText(EDIT_PATH));
	INFO_ADD(L"// AA Script (CE)");
	for (auto &v : vAAScript) {
		INFO_ADD(v);
	}
	INFO_ADD(L"");
	INFO_ADD(L"");
	INFO_ADD(L"// IDC Script (IDA)");
	for (auto &v : vIDCScript) {
		INFO_ADD(v);
	}
	INFO_ADD(L"");
	INFO_ADD(L"");
	INFO_ADD(L"// Info");
	for (auto &v : vInfo) {
		INFO_ADD(v);
	}
	INFO_ADD(L"");
	INFO_ADD(L"");
	return true;
}

// Thread
bool AobScanThread() {
	Frost &f = *frost_dropped;
	Alice &a = *alice_global;
	std::vector<AddrInfoEx> vaix = f.Isx64() ? AobScannerMain64(f) : AobScannerMain(f);

	RunAobScanner(vaix);
	UnlockButton(BUTTON_AOB_SCAN);
	return true;
}

bool VMScanThread() {
	Frost &f = *frost_dropped;
	Alice &a = *alice_global;
	int vm_section = _wtoi(a.GetText(EDIT_VM_SECTION).c_str()); // x86 = 3, x64 = 11
	std::vector<AddrInfoEx> vaix = f.Isx64() ? VMScanner64(f, vm_section) : VMScanner(f, vm_section);

	RunAobScanner(vaix);
	UnlockButton(BUTTON_VM_SCAN);
	return true;
}

bool PolyScanThread() {
	Frost &f = *frost_dropped;
	Alice &a = *alice_global;
	int vm_section = _wtoi(a.GetText(EDIT_VM_SECTION).c_str()); // x86 = 6
	// x86 Only
	if (f.Isx64()) {
		INFO_ADD(L"// x64 is not supported.");
	}
	else {
		std::vector<AddrInfoEx> vaix = PolyScanner(f, vm_section);
		RunAobScanner(vaix);
	}

	UnlockButton(BUTTON_POLY_SCAN);
	return true;
}

bool StackClearScanThread() {
	Frost &f = *frost_dropped;
	Alice &a = *alice_global;
	// x86 Only
	if (f.Isx64()) {
		INFO_ADD(L"// x64 is not supported.");
	}
	else {
		// DEVM Only
		if (GetDEVM()) {
			std::vector<AddrInfoEx> vaix = StackClearScanner(f);
			RunAobScanner(vaix);
		}
		else {
			INFO_ADD(L"// not unvirtualized.");
		}
	}

	UnlockButton(BUTTON_STACK_CLEAR_SCAN);
	return true;
}


// thread
bool RunScanner(Alice &a, int nIDDlgItem) {
	LPTHREAD_START_ROUTINE thread_func = NULL;
	switch (nIDDlgItem) {
	case BUTTON_AOB_SCAN: {
		thread_func = (decltype(thread_func))AobScanThread;
		break;
	}
	case BUTTON_AOB_SCAN_TEST: {
		thread_func = (decltype(thread_func))AobScanTestThread;
		break;
	}
	case BUTTON_VM_SCAN: {
		thread_func = (decltype(thread_func))VMScanThread;
		break;
	}
	case BUTTON_POLY_SCAN: {
		thread_func = (decltype(thread_func))PolyScanThread;
		break;
	}
	case BUTTON_STACK_CLEAR_SCAN: {
		thread_func = (decltype(thread_func))StackClearScanThread;
		break;
	}
	default: {
		break;
	}
	}

	if (!thread_func) {
		return false;
	}

	a.ListView_Clear(LISTVIEW_AOB_SCAN_RESULT);
	INFO_CLEAR();

	// scan thread
	frost_ref_count++;
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)thread_func, NULL, NULL, NULL);
	if (hThread) {
		CloseHandle(hThread);
	}
	return true;
}


// Main Window
#define AR_HEIGHT 240
bool OnCreate(Alice &a) {
	alice_global = &a;
	// Aob Scanner
	a.ListView(LISTVIEW_AOB_SCAN_RESULT, 3, 3, (VIEWER_WIDTH - 6), AR_HEIGHT);
	a.ListView_AddHeader(LISTVIEW_AOB_SCAN_RESULT, L"VA", 120);
	a.ListView_AddHeader(LISTVIEW_AOB_SCAN_RESULT, L"NameTag", 300);
	a.ListView_AddHeader(LISTVIEW_AOB_SCAN_RESULT, L"Mode", 100);
	a.ListView_AddHeader(LISTVIEW_AOB_SCAN_RESULT, L"Patch", 200);
	a.EditBox(EDIT_AOB_SCAN_RESULT_SELECTED, 3, (AR_HEIGHT + 10), L"", (VIEWER_WIDTH - 230));
	a.Button(BUTTON_STACK_CLEAR_SCAN, L"StackClearScan", (VIEWER_WIDTH - 220), (AR_HEIGHT + 10), 100);
	a.Button(BUTTON_AOB_SCAN, L"AobScan", (VIEWER_WIDTH - 110), (AR_HEIGHT + 10), 100);
	// Scan Test
	a.EditBox(EDIT_AOB_SCAN_TEST, 3, (AR_HEIGHT + 30), L"", (VIEWER_WIDTH - 340));
	a.EditBox(EDIT_AOB_SCAN_TEST_RESULT, (VIEWER_WIDTH - 330), (AR_HEIGHT + 30), L"", 100);
	a.ReadOnly(EDIT_AOB_SCAN_TEST_RESULT);
	a.Button(BUTTON_AOB_SCAN_TEST, L"ScanTest", (VIEWER_WIDTH - 220), (AR_HEIGHT + 30), 100);
	//a.Button(BUTTON_AOB_SCAN_TEST_FULL, L"ScanTest(Full)", (VIEWER_WIDTH - 110), (AR_HEIGHT + 30), 100);
	// VM Enter Scanner
	a.CheckBox(CHECK_DEVM, L"unvirtualized", (VIEWER_WIDTH - 430), (AR_HEIGHT + 50), BST_CHECKED);
	a.StaticText(STATIC_VM_SECTION, L"VM Section : ", (VIEWER_WIDTH - 330), (AR_HEIGHT + 50));
	a.EditBox(EDIT_VM_SECTION, (VIEWER_WIDTH - 220), (AR_HEIGHT + 50), L"3", 100);
	a.Button(BUTTON_VM_SCAN, L"VM Enter Scan", (VIEWER_WIDTH - 110), (AR_HEIGHT + 50), 100);
	a.Button(BUTTON_POLY_SCAN, L"POLY Scan", (VIEWER_WIDTH - 110), (AR_HEIGHT + 70), 100);
	// Info
	a.TextArea(TEXTAREA_INFO, 3, 360, (VIEWER_WIDTH - 6), 200);
	a.ReadOnly(TEXTAREA_INFO);
	a.StaticText(STATIC_PATH, L"File Path :", 10, (VIEWER_HEIGHT - 30));
	a.EditBox(EDIT_PATH, 80, (VIEWER_HEIGHT - 30), L"Please Drop File", (VIEWER_WIDTH - 90));
	a.ReadOnly(EDIT_PATH);
	return true;
}

// Button
bool OnCommand(Alice &a, int nIDDlgItem) {
	switch (nIDDlgItem) {
	case BUTTON_AOB_SCAN:
	case BUTTON_AOB_SCAN_TEST:
	case BUTTON_VM_SCAN:
	case BUTTON_POLY_SCAN:
	case BUTTON_STACK_CLEAR_SCAN:
	{
		// file is not opened.
		if (!frost_dropped) {
			return false;
		}
		SetDEVM(a.CheckBoxStatus(CHECK_DEVM));
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
	if (nIDDlgItem == LISTVIEW_AOB_SCAN_RESULT) {
		std::wstring text_va;
		std::wstring text_name_tag;
		a.ListView_Copy(LISTVIEW_AOB_SCAN_RESULT, LVA_VA, text_va, false);
		a.ListView_Copy(LISTVIEW_AOB_SCAN_RESULT, LVA_NAME_TAG, text_name_tag, true, 4096);
		a.SetText(EDIT_AOB_SCAN_RESULT_SELECTED, text_va + L" | " + text_name_tag);
		return true;
	}
	return true;
}

// Drop -> Open
bool OnDropFile(Alice &a, wchar_t *drop) {
	INFO_CLEAR();
	if (!Dropped_Close()) {
		INFO_ADD(L"// Error! Previous task is still running.");
		return false;
	}

	a.SetText(EDIT_PATH, drop);
	INFO_ADD(drop);
	Dropped_Open(drop);

	if (!Dropped_Parse()) {
		INFO_ADD(L"// Error! Unable to open PE file.");
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
