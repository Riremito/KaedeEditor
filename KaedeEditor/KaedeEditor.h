#ifndef __KAEDE_EDITOR_H__
#define __KAEDE_EDITOR_H__

#include"Simple.h"
#include"Frost.h"
#include"StringPool.h"
#include"Formatter.h"
#include"AobScanner.h"

void SetDEVM(bool flag);
bool GetDEVM();

#define VIEWER_WIDTH 800
#define VIEWER_HEIGHT 600

enum SubControl {
	RESERVED,
	STATIC_PATH,
	EDIT_PATH,
	TEXTAREA_INFO,
	LISTVIEW_AOB_SCAN_RESULT,
	EDIT_AOB_SCAN_RESULT_SELECTED,
	CHECK_DEVM,
	COMBOBOX_SCANNER,
	BUTTON_AOBSCAN,
	STATIC_VM_SECTION,
	EDIT_VM_SECTION,
	EDIT_TEST_SCAN,
	BUTTON_TEST_SCAN,
	CHECK_TEST_SCAN_ALL,
};

enum ListViewIndex {
	LVA_VA,
	LVA_NAME_TAG,
	LVA_MODE,
	LVA_PATCH,
};

enum ScannerIndex {
	SI_Main = 0,
	SI_Self_Crash,
	//SI_PacketFunctions,
	//SI_OtherFunctions,
	SI_Themida_VMProtect,
	SI_ASProtect,
	//SI_EMS_7X,
	//SI_JMS_309,
	//SI_StringPool,
	SI_127_0_0_1,
};

const std::wstring ScannerList[] = {
	L"Main",
	L"Self Crash",
	//L"Packet Functions",
	//L"Other Functions",
	L"Themida & VMProtect",
	L"ASProtect",
	//L"EMS v7X EntryPoint",
	//L"JMS v309+",
	//L"StringPool",
	L"127.0.0.1",
};

#define INFO_ADD(str) a.AddText(TEXTAREA_INFO, str)
#define INFO_CLEAR()  a.SetText(TEXTAREA_INFO, L"")

#endif
