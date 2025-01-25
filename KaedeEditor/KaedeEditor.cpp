#include"KaedeEditor.h"

bool flag_devm = true;
void SetDEVM(bool flag) {
	flag_devm = flag;
}

bool GetDEVM() {
	return flag_devm;
}

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
void ScanButtonLock(int nIDDlgItem) {
	Alice &a = *alice_global;
	frost_ref_count++;
	a.ChangeState(nIDDlgItem, FALSE);
}

void ScanButtonUnlock(int nIDDlgItem) {
	Alice &a = *alice_global;
	frost_ref_count--;
	a.ChangeState(nIDDlgItem, TRUE);
}


// Scanner
bool RunAobScanner(std::vector<AddrInfoEx> &vAddrInfoEx, int nIDDlgItem) {
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
			// IDC Script (IDA)
			if (v.tag.length() && v.tag.at(0) == L'?') {
				vIDCScript.push_back(L"set_name(0x" + wVA + L", \"" + v.tag + L"\");");
				if (!v.patch.length()) {
					continue;
				}
			}
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
		}
		vInfo.push_back(wVA + L" // " + v.tag);
	}

	INFO_ADD(L"// Kaede Editor");
	INFO_ADD(L"// File = " + a.GetText(EDIT_PATH));
	if (vAAScript.size()) {
		INFO_ADD(L"// AA Script (CE)");
		for (auto &v : vAAScript) {
			INFO_ADD(v);
		}
		INFO_ADD(L"");
		INFO_ADD(L"");
	}
	if (vIDCScript.size()) {
		INFO_ADD(L"// IDC Script (IDA)");
		for (auto &v : vIDCScript) {
			INFO_ADD(v);
		}
		INFO_ADD(L"");
		INFO_ADD(L"");
	}
	if (vInfo.size()) {
		INFO_ADD(L"// Info");
		for (auto &v : vInfo) {
			INFO_ADD(v);
		}
		INFO_ADD(L"");
		INFO_ADD(L"");
	}

	ScanButtonUnlock(nIDDlgItem);
	return true;
}

// Thread
bool Thread_Main() {
	Frost &f = *frost_dropped;
	Alice &a = *alice_global;
	std::vector<AddrInfoEx> vaix = f.Isx64() ? Scanner_Main64(f) : Scanner_Main(f);

	RunAobScanner(vaix, BUTTON_AOBSCAN);
	return true;
}

bool Thread_Client_Edit() {
	Frost &f = *frost_dropped;
	Alice &a = *alice_global;
	std::vector<AddrInfoEx> vaix;
	// x86 Only
	if (f.Isx64()) {
		INFO_ADD(L"// x64 is not supported.");
	}
	else {
		vaix = Scanner_Client_Edit(f);
	}

	RunAobScanner(vaix, BUTTON_AOBSCAN);
	return true;
}

bool Thread_SelfCrash() {
	Frost &f = *frost_dropped;
	Alice &a = *alice_global;
	std::vector<AddrInfoEx> vaix;
	// x86 Only
	if (f.Isx64()) {
		INFO_ADD(L"// x64 is not supported.");
	}
	else {
		// DEVM Only
		if (GetDEVM()) {
			vaix = Scanner_SelfCrash(f);
		}
		else {
			INFO_ADD(L"// not unvirtualized.");
		}
	}

	RunAobScanner(vaix, BUTTON_AOBSCAN);
	return true;
}

bool Thread_Themida_VMProtect() {
	Frost &f = *frost_dropped;
	Alice &a = *alice_global;
	int vm_section = _wtoi(a.GetText(EDIT_VM_SECTION).c_str()); // x86 = 3, x64 = 11
	std::vector<AddrInfoEx> vaix = f.Isx64() ? Scanner_Themida_VMProtect64(f, vm_section) : Scanner_Themida_VMProtect(f, vm_section);

	RunAobScanner(vaix, BUTTON_AOBSCAN);
	return true;
}

bool Thread_ASProtect() {
	Frost &f = *frost_dropped;
	Alice &a = *alice_global;
	std::vector<AddrInfoEx> vaix;
	int vm_section = _wtoi(a.GetText(EDIT_VM_SECTION).c_str()); // x86 = 6
	// x86 Only
	if (f.Isx64()) {
		INFO_ADD(L"// x64 is not supported.");
	}
	else {
		vaix = Scanner_ASProtect(f, vm_section);
	}

	RunAobScanner(vaix, BUTTON_AOBSCAN);
	return true;
}

bool Thread_Functions_Packet() {
	Frost &f = *frost_dropped;
	Alice &a = *alice_global;
	std::vector<AddrInfoEx> vaix = f.Isx64() ? Scanner_Functions_Packet64(f) : Scanner_Functions_Packet(f);

	RunAobScanner(vaix, BUTTON_AOBSCAN);
	return true;
}

bool Thread_Functions_Others() {
	Frost &f = *frost_dropped;
	Alice &a = *alice_global;
	std::vector<AddrInfoEx> vaix = f.Isx64() ? Scanner_Functions_Others64(f) : Scanner_Functions_Others(f);

	RunAobScanner(vaix, BUTTON_AOBSCAN);
	return true;
}

bool Thread_127_0_0_1() {
	Frost &f = *frost_dropped;
	Alice &a = *alice_global;
	std::vector<AddrInfoEx> vaix = Scanner_127_0_0_1(f);

	if (!vaix.size()) {
		INFO_ADD(L"// 127.0.0.1 is not found.");
	}

	RunAobScanner(vaix, BUTTON_AOBSCAN);
	return true;
}

bool RunScanner(Alice &a, ScannerIndex si) {
	LPTHREAD_START_ROUTINE thread_func = NULL;
	switch (si) {
	case SI_Main: {
		thread_func = (decltype(thread_func))Thread_Main;
		break;
	}
	case SI_Self_Crash: {
		thread_func = (decltype(thread_func))Thread_SelfCrash;
		break;
	}
	case SI_Client_Edit: {
		thread_func = (decltype(thread_func))Thread_Client_Edit;
		break;
	}
	case SI_Themida_VMProtect: {
		thread_func = (decltype(thread_func))Thread_Themida_VMProtect;
		break;
	}
	case SI_ASProtect: {
		thread_func = (decltype(thread_func))Thread_ASProtect;
		break;
	}
	case SI_Functions_Packet: {
		thread_func = (decltype(thread_func))Thread_Functions_Packet;
		break;
	}
	case SI_Functions_Others: {
		thread_func = (decltype(thread_func))Thread_Functions_Others;
		break;
	}
	case SI_127_0_0_1: {
		thread_func = (decltype(thread_func))Thread_127_0_0_1;
		break;
	}
	default: {
		break;
	}
	}

	if (!thread_func) {
		return false;
	}
	ScanButtonLock(BUTTON_AOBSCAN);

	a.ListView_Clear(LISTVIEW_AOB_SCAN_RESULT);
	INFO_CLEAR();

	// scan thread
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)thread_func, NULL, NULL, NULL);
	if (hThread) {
		CloseHandle(hThread);
	}
	return true;
}

bool TestScanWrapper() {
	Frost &f = *frost_dropped;
	Alice &a = *alice_global;
	std::vector<AddrInfoEx> vaix;
	a.ListView_Clear(LISTVIEW_AOB_SCAN_RESULT);
	INFO_CLEAR();
	INFO_ADD(L"// Test Scan");
	ScanButtonLock(BUTTON_TEST_SCAN);
	vaix = TestScan(f, a.GetText(EDIT_TEST_SCAN), a.CheckBoxStatus(CHECK_TEST_SCAN_ALL));
	RunAobScanner(vaix, BUTTON_TEST_SCAN);
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
	// Info
	a.TextArea(TEXTAREA_INFO, 3, 360, (VIEWER_WIDTH - 6), 200);
	a.ReadOnly(TEXTAREA_INFO);
	a.StaticText(STATIC_PATH, L"File Path :", 10, (VIEWER_HEIGHT - 30));
	a.EditBox(EDIT_PATH, 80, (VIEWER_HEIGHT - 30), L"Please Drop File", (VIEWER_WIDTH - 90));
	a.ReadOnly(EDIT_PATH);

	// New
	a.EditBox(EDIT_AOB_SCAN_RESULT_SELECTED, 3, (AR_HEIGHT + 10), L"", (VIEWER_WIDTH - 6));
	a.ComboBox(COMBOBOX_SCANNER, (VIEWER_WIDTH - 3) - 150 - 110, (AR_HEIGHT + 30), 150);
	a.Button(BUTTON_AOBSCAN, L"AobScan", (VIEWER_WIDTH - 3) - 100, (AR_HEIGHT + 30), 100);
	a.StaticText(STATIC_VM_SECTION, L"VM Section : ", (VIEWER_WIDTH - 3) - 100 - 110, (AR_HEIGHT + 50));
	a.EditBox(EDIT_VM_SECTION, (VIEWER_WIDTH - 3) - 100, (AR_HEIGHT + 50), L"3", 100);
	a.CheckBox(CHECK_DEVM, L"Unvirtualized", (VIEWER_WIDTH - 3) - 100, (AR_HEIGHT + 70), BST_CHECKED);

	for (auto v : ScannerList) {
		a.ComboBoxAdd(COMBOBOX_SCANNER, v);
	}
	a.ComboBoxSelect(COMBOBOX_SCANNER, 0);

	// test
	a.EditBox(EDIT_TEST_SCAN, 3, (AR_HEIGHT + 30), L"", 300);
	a.Button(BUTTON_TEST_SCAN, L"TestScan", 310, (AR_HEIGHT + 30), 100);
	a.CheckBox(CHECK_TEST_SCAN_ALL, L"All", 420, (AR_HEIGHT + 30));
	return true;
}

// Button
bool OnCommand(Alice &a, int nIDDlgItem) {
	switch (nIDDlgItem) {
	case BUTTON_AOBSCAN:
	{
		// file is not opened.
		if (!frost_dropped) {
			return false;
		}
		SetDEVM(a.CheckBoxStatus(CHECK_DEVM));
		ScannerIndex si = (ScannerIndex)a.ComboBoxSelected(COMBOBOX_SCANNER);
		RunScanner(a, si);
		return true;
	}
	case BUTTON_TEST_SCAN: {
		if (!frost_dropped) {
			return false;
		}
		TestScanWrapper();
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
