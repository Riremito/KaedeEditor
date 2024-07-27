#include"Simple.h"

#if defined _M_IX86
# pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_IA64
# pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='ia64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
# pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
# pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

// global variables
std::vector<HWND> Alice::window_list;
std::vector<Alice*> Alice::list;

// public
Alice::Alice(std::wstring wClassName, std::wstring wWindowName, int nWidth, int nHeight, HINSTANCE hInstance) {
	main_hwnd = NULL;
	main_class_name = wClassName;
	main_window_name = wWindowName;
	main_width = nWidth;
	main_height = nHeight;
	main_instance = hInstance;

	SetOnCreate(NULL);
	SetOnCommand(NULL);
	SetOnCommandEx(NULL);
	SetOnNotify(NULL);
	SetOnDropFile(NULL);
	SetCallback(NULL, CT_UNDEFINED);
}

Alice::~Alice() {
	if (main_hwnd) {
		UnRegister();
	}
}

bool Alice::Run() {
	if (!Register()) {
		if (!UnRegister()) {
			return false;
		}
		if (!Register()) {
			return false;
		}
	}

	HWND hWnd = CreateWindowExW(NULL, main_class_name.c_str(), main_window_name.c_str(), (WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME), CW_USEDEFAULT, CW_USEDEFAULT, main_width, main_height, NULL, NULL, main_instance, this);
	if (!hWnd) {
		return false;
	}

	list.push_back(this);
	window_list.push_back(hWnd);
	return true;
}

bool Alice::IsAlive() {
	for (auto hwnd: window_list) {
		if (hwnd == main_hwnd) {
			return true;
		}
	}
	return false;
}

bool Alice::DetectInvalidWindow() {
	for (size_t i = 0; i < window_list.size(); i++) {
		if (!IsWindow(window_list[i])) {
			list[i]->UnRegister();
			list.erase(list.begin() + i);
			window_list.erase(window_list.begin() + i);
			return true;
		}
	}
	return false;
}

bool Alice::Wait() {
	MSG msg;
	memset(&msg, 0, sizeof(msg));

	do {
		while (GetMessageW(&msg, NULL, NULL, NULL) > 0) {
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		}
		DetectInvalidWindow();
	} while (window_list.size());

	return true;
}

// private
LRESULT CALLBACK Alice::AliceProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
	Alice *a = (Alice *)GetWindowLongPtrW(hWnd, GWLP_USERDATA);

	switch (Msg) {
	case WM_CREATE:
	{
		if (!a) {
			CREATESTRUCTW *cs = decltype(cs)(lParam);
			a = (Alice *)cs->lpCreateParams;
			Resize(hWnd, cs->cx, cs->cy);
			a->main_hwnd = hWnd;
			a->OnCreate(*a);
			if (a->on_dropfile) {
				DragAcceptFiles(hWnd, TRUE);
			}
			ShowWindow(hWnd, SW_SHOW);
			SetWindowLongPtrW(hWnd, GWLP_USERDATA, (ULONG_PTR)a);
		}
		break;
	}
	case WM_COMMAND:
	{
		if (a) {
			if (!a->OnCommand(*a, LOWORD(wParam))) {
				a->OnCommandEx(*a, LOWORD(wParam), HIWORD(wParam));
			}
		}
		break;
	}
	case WM_NOTIFY:
	{
		NMHDR *nh = (NMHDR *)lParam;
		if (a) {
			if (nh->code == LVN_ITEMCHANGED) {
				a->OnNotify(*a, LOWORD(wParam));
			}
		}
		break;
	}
	case WM_DROPFILES: {
		if (a) {
			wchar_t drop[MAX_PATH] = { 0 };
			DragQueryFileW((HDROP)wParam, 0, drop, _countof(drop) - 1);
			DragFinish((HDROP)wParam);
			a->OnDropFile(*a, drop);
		}
		break;
	}
	case WM_MOUSEMOVE:
	{
		static HCURSOR arrow = LoadCursorW(NULL, IDC_ARROW);
		if (arrow) {
			SetCursor(arrow);
		}
		break;
	}
	case WM_LBUTTONUP:
	{
		SetFocus(hWnd);
		break;
	}
	case WM_CLOSE:
	{
		ShowWindow(hWnd, SW_HIDE);
		break;
	}
	case WM_DESTROY:
	{
		PostQuitMessage(0);
		break;
	}
	default:
		break;
	}

	if (a) {
		switch (a->GetCallbackType()) {
		case CT_CALL:
		{
			a->Callback(hWnd, Msg, wParam, lParam);
			break;
		}
		case CT_INTERRUPTION:
		{
			return a->Callback(hWnd, Msg, wParam, lParam);
		}
		default:
			break;
		}
	}

	return DefWindowProcW(hWnd, Msg, wParam, lParam);
}

bool Alice::Resize(HWND hWnd, int cx, int cy) {
	if (!hWnd) {
		return false;
	}

	RECT window_rect;
	memset(&window_rect, 0, sizeof(window_rect));

	if (!GetWindowRect(hWnd, &window_rect)) {
		return false;
	}

	RECT client_rect;
	memset(&client_rect, 0, sizeof(client_rect));
	if (!GetClientRect(hWnd, &client_rect)) {
		return false;
	}

	if (!SetWindowPos(hWnd, HWND_TOP, NULL, NULL, (cx + (window_rect.right - window_rect.left) - (client_rect.right - client_rect.left)), (cy + (window_rect.bottom - window_rect.top) - (client_rect.bottom - client_rect.top)), SWP_NOMOVE)) {
		return false;
	}

	return true;
}

bool Alice::Register() {
	WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
	wc.hbrBackground = (HBRUSH)COLOR_WINDOW;

	wc.hInstance = main_instance;
	if (callback_type == CT_MANUAL && manual_callback) {
		wc.lpfnWndProc = manual_callback;
	}
	else {
		wc.lpfnWndProc = AliceProc;
	}

	wc.lpszClassName = main_class_name.c_str();
	wc.style = CS_HREDRAW | CS_VREDRAW;

	if (!RegisterClassExW(&wc)) {
		return false;
	}

	return true;
}
bool Alice::UnRegister() {
	if (!UnregisterClassW(main_class_name.c_str(), main_instance)) {
		return false;
	}

	return true;
}