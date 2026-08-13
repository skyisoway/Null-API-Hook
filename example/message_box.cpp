#include "example.h"

typedef int (*ProtoMessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
typedef BOOL (*ProtoBeep)(DWORD dwFreq, DWORD dwDuration);

null::HookState hMessageBoxW{};
null::HookState hBeep{};

int HookMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	std::wcout << L"MessageBoxW: " << lpText << std::endl;

	return ((ProtoMessageBoxW)hMessageBoxW.function.pOrigin)(hWnd, L"Hello from MessageBoxW hook!", lpCaption, uType);
}

BOOL HookBeep(DWORD dwFreq, DWORD dwDuration)
{
	std::cout << "Beep intercepted: freq=" << dwFreq << ", duration=" << dwDuration << std::endl;

	return ((ProtoBeep)hBeep.function.pOrigin)(1000, 500);
}

void MessageBoxExemple()
{
	HMODULE hUser32Module = LoadLibraryA("User32.dll");
	HMODULE hKernel32Module = LoadLibraryA("KERNEL32.DLL");

	null::LibraryState lUser32State{};
	null::LibraryState lKernel32State{};

	if (!null::CreateHook(&lUser32State, &hMessageBoxW, hUser32Module, "MessageBoxW", HookMessageBoxW))
	{
		std::cout << "Error create MessageBoxW hook" << std::endl;
		return;
	}

	if (!null::CreateHook(&lKernel32State, &hBeep, hKernel32Module, "Beep", HookBeep))
	{
		std::cout << "Error create Beep hook" << std::endl;

		return;
	}

	MessageBoxW(nullptr, L"Original text", L"Test", MB_OK);

	Beep(500, 200);

	null::DisableHook(&hMessageBoxW);
	null::DisableHook(&hBeep);

	MessageBoxW(nullptr, L"Hook disabled", L"Test", MB_OK);

	Beep(500, 200);

	null::EnableHook(&hMessageBoxW);
	null::EnableHook(&hBeep);

	MessageBoxW(nullptr, L"Hook enabled again", L"Test", MB_OK);

	Beep(500, 200);

	null::DeleteHook(&hMessageBoxW);
	null::DeleteHook(&hBeep);

	return;
}
