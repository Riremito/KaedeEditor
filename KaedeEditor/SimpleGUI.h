#ifndef __ALICE_H__
#define __ALICE_H__

class Alice {
	// global
public:
	enum CallbackType {
		CT_UNDEFINED,
		CT_CALL,
		CT_MANUAL,
		CT_INTERRUPTION
	};

	static bool Wait();

private:
	static std::vector<HWND> window_list;
	static std::vector<Alice*> list;

	static bool DetectInvalidWindow();

	// main
private:
	HWND main_hwnd;
	std::wstring main_class_name;
	std::wstring main_window_name;
	int main_width;
	int main_height;
	HINSTANCE main_instance;

	static LRESULT CALLBACK AliceProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
	static bool Resize(HWND hWnd, int cx, int cy);
	bool Register();
	bool UnRegister();

public:
	Alice(std::wstring wClassName, std::wstring wWindowName, int nWidth, int nHeight, HINSTANCE hInstance);
	~Alice();
	bool Run();
	bool IsAlive();

	// External
private:
	bool (*on_create)(Alice&);
	bool (*on_command)(Alice&, int);
	bool (*on_commandex)(Alice&, int, int);
	bool (*on_notify)(Alice&, int);
	bool (*on_dropfile)(Alice&, wchar_t*);
	bool OnCreate(Alice &a);
	bool OnCommand(Alice &a, int nIDDlgItem);
	bool OnCommandEx(Alice &a, int nIDDlgItem, int msg);
	bool OnNotify(Alice &a, int nIDDlgItem);
	bool OnDropFile(Alice &a, wchar_t *drop);

	decltype(DefWindowProcW) *manual_callback;
	CallbackType callback_type;

public:
	bool SetOnCreate(bool(*function)(Alice&));
	bool SetOnCommand(bool(*function)(Alice&, int));
	bool SetOnCommandEx(bool(*function)(Alice&, int, int));
	bool SetOnNotify(bool(*function)(Alice&, int));
	bool SetOnDropFile(bool(*function)(Alice&, wchar_t*));
	bool SetCallback(decltype(DefWindowProcW) *function, CallbackType ct);
	CallbackType GetCallbackType();
	LRESULT CALLBACK Callback(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
	HWND GetMainHWND();

	// Control
private:
	std::vector<size_t> control_id_list;
	std::vector<HWND> control_hwnd_list;

	bool SetFont(size_t nIDDlgItem);
	int AutoWidth(std::wstring wText);
public:
	// create
	bool StaticText(size_t nIDDlgItem, std::wstring wText, int X, int Y);
	bool Button(size_t nIDDlgItem, std::wstring wText, int X, int Y, int nWidth = 0);
	bool CheckBox(size_t nIDDlgItem, std::wstring wText, int X, int Y, UINT uCheck = BST_UNCHECKED);
	bool EditBox(size_t nIDDlgItem, int X, int Y, std::wstring wText = L"", int nWidth = 0);
	bool TextArea(size_t nIDDlgItem, int X, int Y, int nWidth, int nHeight);
	bool ListView(size_t nIDDlgItem, int X, int Y, int nWidth, int nHeight);
	bool ComboBox(size_t nIDDlgItem, int X, int Y, int nWidth);
	// do
	bool ReadOnly(size_t nIDDlgItem, WPARAM wParam = true);
	bool ChangeState(size_t nIDDlgItem, BOOL bEnable);
	bool SetText(size_t nIDDlgItem, std::wstring wText);
	bool AddText(size_t nIDDlgItem, std::wstring wText);
	std::wstring GetText(size_t nIDDlgItem);
	LRESULT CheckBoxStatus(size_t nIDDlgItem);
	bool ComboBoxAdd(size_t nIDDlgItem, std::wstring wText);
	bool ComboBoxSelect(size_t nIDDlgItem, int index);
	LRESULT ComboBoxSelected(size_t nIDDlgItem);
	std::wstring ComboBoxGetText(size_t nIDDlgItem, int index);
	std::wstring ComboBoxGetSelectedText(size_t nIDDlgItem);
	bool Embed(HWND hWnd, int nWidth, int nHeight);

	// ListView
private:
	std::vector<size_t> listview_id_list;
	std::vector<int> listview_previous_selected;

	LRESULT ListView_HeaderCount(size_t nIDDlgItem);
	LRESULT ListView_LineCount(size_t nIDDlgItem);
	bool ListView_AutoScroll(size_t nIDDlgItem);
	bool ListView_GetPreviousSelected(size_t nIDDlgItem, int &Selected);
	bool ListView_SetPreviousSelected(size_t nIDDlgItem, int Selected);
public:
	bool ListView_AddHeader(size_t nIDDlgItem, std::wstring wHeader, int Width);
	bool ListView_AddItem(size_t nIDDlgItem, int index, std::wstring wText);
	bool ListView_AddItemWOS(size_t nIDDlgItem, int index, std::wstring wText);
	bool ListView_UpdateItem(size_t nIDDlgItem, int index, int line, std::wstring wText);
	bool ListView_Clear(size_t nIDDlgItem);
	bool ListView_Copy(size_t nIDDlgItem, int index, std::wstring &wText, bool block = false, size_t size = 256);
	bool ListView_Find(size_t nIDDlgItem, int index, std::wstring &wText, int &line);
};

#endif