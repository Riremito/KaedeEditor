#include"Simple.h"
#include"Frost.h"
#include"StringPool.h"
#include"Formatter.h"
#include"AobScanner.h"

#define VIEWER_WIDTH 800
#define VIEWER_HEIGHT 600

enum SubControl {
	RESERVED,
	STATIC_PATH,
	EDIT_PATH,
	BUTTON_AOBSCAN,
	LISTVIEW_AOBSCAN_RESULT,
	EDIT_SELECTED,
	TEXTAREA_INFO,
	BUTTON_VM_SCAN,
	STATIC_VM_SECTION,
	EDIT_VM_SECTION
};

enum ListViewIndex {
	LVA_VA,
	LVA_NAME_TAG,
	LVA_MODE,
	LVA_PATCH,
};

#define ADDINFO(str) a.AddText(TEXTAREA_INFO, str)
#define SCANINFO(asr) ADDINFO(L"[" #asr L"]\r\nAddress: " + (f.Isx64() ? QWORDtoString(asr.VA, true) : DWORDtoString((DWORD)asr.VA)) + L"\r\nOffset : " + DWORDtoString((DWORD)asr._RRA))
#define ADDRTOSTRING(ai) (f.Isx64() ? QWORDtoString(ai.VA, true) : DWORDtoString((DWORD)ai.VA))

bool AccessTest(ULONG_PTR uAddr) {
	__try {
		if (IsBadReadPtr((void *)uAddr, 2)) {
			return false;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}

	return true;
}

void SetButtonState(Alice &a, BOOL bEnable) {
	a.ChangeState(BUTTON_AOBSCAN, bEnable);
	a.ChangeState(BUTTON_VM_SCAN, bEnable);
}

bool AobScanThread(Alice &a) {
	std::wstring path = a.GetText(EDIT_PATH);
	ADDINFO(L"File Path = " + path);
	a.ListView_Clear(LISTVIEW_AOBSCAN_RESULT);
	a.SetText(TEXTAREA_INFO, L"");

	Frost f(path.c_str());

	ADDINFO(L"Loading...");
	if (!f.Parse()) {
		ADDINFO(L"Error! unable to open exe file.");
		SetButtonState(a, TRUE);
		return false;
	}

	if (f.Isx64()) {
		ADDINFO(L"Error! x64 is not supported now.");
		SetButtonState(a, TRUE);
		return false;
	}

	std::vector<std::wstring> vAAScript;
	std::vector<std::wstring> vIDCScript;
	std::vector<std::wstring> vInfo;

	vAAScript.push_back(L"[Enable]");
	for (auto &v : AobScannerMain(f)) {
		std::wstring wVA = v.info.VA ? DWORDtoString((DWORD)v.info.VA) : L"ERROR";
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
	ADDINFO(L"// AA Script (CE)");
	for (auto &v : vAAScript) {
		ADDINFO(v);
	}
	ADDINFO(L"");
	ADDINFO(L"// IDC Script (IDA)");
	for (auto &v : vIDCScript) {
		ADDINFO(v);
	}
	ADDINFO(L"");
	ADDINFO(L"// Info");
	for (auto &v : vInfo) {
		ADDINFO(v);
	}
	ADDINFO(L"");
	ADDINFO(L"OK!");
	SetButtonState(a, TRUE); // unlock button
	return true;
}

bool VMScanThread(Alice &a) {
	std::wstring path = a.GetText(EDIT_PATH);
	ADDINFO(L"File Path = " + path);
	a.ListView_Clear(LISTVIEW_AOBSCAN_RESULT);
	a.SetText(TEXTAREA_INFO, L"");

	Frost f(path.c_str());

	ADDINFO(L"Loading...");
	if (!f.Parse()) {
		ADDINFO(L"Error! unable to open exe file.");
		SetButtonState(a, TRUE);
		return false;
	}

	if (f.Isx64()) {
		ADDINFO(L"Error! x64 is not supported now.");
		SetButtonState(a, TRUE);
		return false;
	}

	int vm_section = _wtoi(a.GetText(EDIT_VM_SECTION).c_str());
	for (auto &v : VMScanner(f, vm_section)) {
		std::wstring wVA = v.info.VA ? DWORDtoString((DWORD)v.info.VA) : L"ERROR";
		a.ListView_AddItem(LISTVIEW_AOBSCAN_RESULT, LVA_VA, wVA);
		a.ListView_AddItem(LISTVIEW_AOBSCAN_RESULT, LVA_NAME_TAG, v.tag);
		a.ListView_AddItem(LISTVIEW_AOBSCAN_RESULT, LVA_MODE, v.mode);
		a.ListView_AddItem(LISTVIEW_AOBSCAN_RESULT, LVA_PATCH, v.info.VA ? v.patch : L"ERROR");
	}

	ADDINFO(L"OK!");
	SetButtonState(a, TRUE); // unlock button
	return true;
}

// main thread
bool TryAobScan(Alice &a) {
	SetButtonState(a, FALSE); // lock button
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)AobScanThread, (LPVOID)&a, NULL, NULL);
	if (hThread) {
		CloseHandle(hThread);
	}
	return true;
}

bool TryVMScan(Alice &a) {
	SetButtonState(a, FALSE);
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)VMScanThread, (LPVOID)&a, NULL, NULL);
	if (hThread) {
		CloseHandle(hThread);
	}
	return true;
}

// gui part
bool OnCreate(Alice &a) {
	a.StaticText(STATIC_PATH, L"File Path :", 3, 3);
	a.EditBox(EDIT_PATH, 80, 3, L"Please Drop File", 500);
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

bool OnCommand(Alice &a, int nIDDlgItem) {
	switch (nIDDlgItem) {
	case BUTTON_AOBSCAN: {
		TryAobScan(a);
		return true;
	}
	case BUTTON_VM_SCAN: {
		TryVMScan(a);
		return true;
	}
	default: {
		break;
	}
	}
	return true;
}

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

bool OnDropFile(Alice &a, wchar_t *drop) {
	a.SetText(EDIT_PATH, drop);
	return true;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
	Alice a(L"KaedeEditorClass", L"Kaede Editor test", VIEWER_WIDTH, VIEWER_HEIGHT, hInstance);
	a.SetOnCreate(OnCreate);
	a.SetOnCommand(OnCommand);
	a.SetOnNotify(OnNotify);
	a.SetOnDropFile(OnDropFile);
	a.Run();
	a.Wait();
	return 0;
}
