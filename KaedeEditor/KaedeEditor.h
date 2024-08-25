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

#define INFO_ADD(str) a.AddText(TEXTAREA_INFO, str)
#define INFO_CLEAR()  a.SetText(TEXTAREA_INFO, L"")

#endif
