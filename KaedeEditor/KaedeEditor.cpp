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
};

enum ListViewIndex {
	LVA_VA,
	LVA_NAME_TAG,
};

typedef struct {
	bool OK;
	Alice *a;
	std::wstring path;
	ULONG_PTR Addr_Key;
	ULONG_PTR Addr_Array;
	int ArraySize;
	UINT codepage;
} ThreadArg;

ThreadArg gThreadArg;
std::vector<std::wstring> dumpdata;
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

bool AobScanThread(Alice &a) {
	std::wstring path = a.GetText(EDIT_PATH);
	ADDINFO(L"File Path = " + path);
	a.ListView_Clear(LISTVIEW_AOBSCAN_RESULT);
	dumpdata.clear();

	Frost f(path.c_str());

	ADDINFO(L"Loading...");
	if (!f.Parse()) {
		ADDINFO(L"Error! unable to open exe file.");
		a.ChangeState(BUTTON_AOBSCAN, TRUE);
		return false;
	}

	if (f.Isx64()) {
		ADDINFO(L"Error! x64 is not supported now.");
		a.ChangeState(BUTTON_AOBSCAN, TRUE);
		return false;
	}

	std::vector<AddrInfo> test = f.AobScanFin(L"CC CC CC CC CC");

	for (auto &v : test) {
		a.ListView_AddItem(LISTVIEW_AOBSCAN_RESULT, LVA_VA, DWORDtoString(v.VA));
		a.ListView_AddItem(LISTVIEW_AOBSCAN_RESULT, LVA_NAME_TAG, DWORDtoString(v.VA));
	}

	ADDINFO(L"OK!");
	a.ChangeState(BUTTON_AOBSCAN, TRUE); // unlock button
	return true;
}

// main thread
bool TryAobScan(Alice &a) {
	a.ChangeState(BUTTON_AOBSCAN, FALSE); // lock button
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)AobScanThread, (LPVOID)&a, NULL, NULL);
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
	a.ListView_AddHeader(LISTVIEW_AOBSCAN_RESULT, L"NameTag", (VIEWER_WIDTH - 150));
	a.EditBox(EDIT_SELECTED, 3, 340, L"", (VIEWER_WIDTH - 6));
	a.TextArea(TEXTAREA_INFO, 3, 360, (VIEWER_WIDTH - 6), 200);
	a.ReadOnly(TEXTAREA_INFO);
	return true;
}

bool OnCommand(Alice &a, int nIDDlgItem) {
	switch (nIDDlgItem) {
	case BUTTON_AOBSCAN: {
		TryAobScan(a);
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
	gThreadArg.OK = true;
	Alice a(L"KaedeEditorClass", L"Kaede Editor test", VIEWER_WIDTH, VIEWER_HEIGHT, hInstance);
	a.SetOnCreate(OnCreate);
	a.SetOnCommand(OnCommand);
	a.SetOnNotify(OnNotify);
	a.SetOnDropFile(OnDropFile);
	a.Run();
	a.Wait();
	return 0;
}
