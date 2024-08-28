#ifndef __KAEDE_EDITOR_H__
#define __KAEDE_EDITOR_H__

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
	TEXTAREA_INFO,
	LISTVIEW_AOB_SCAN_RESULT,
	EDIT_AOB_SCAN_RESULT_SELECTED,
	BUTTON_AOB_SCAN,
	EDIT_AOB_SCAN_TEST,
	EDIT_AOB_SCAN_TEST_RESULT,
	BUTTON_AOB_SCAN_TEST,
	BUTTON_AOB_SCAN_TEST_FULL,
	STATIC_VM_SECTION,
	EDIT_VM_SECTION,
	BUTTON_VM_SCAN,
	BUTTON_STACK_CLEAR_SCAN,
	CHECK_DEVM,
};

enum ListViewIndex {
	LVA_VA,
	LVA_NAME_TAG,
	LVA_MODE,
	LVA_PATCH,
};

#define INFO_ADD(str) a.AddText(TEXTAREA_INFO, str)
#define INFO_CLEAR()  a.SetText(TEXTAREA_INFO, L"")

#endif
