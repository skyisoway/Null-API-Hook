# Null-API-Hook
[![Windows](https://img.shields.io/badge/Windows-supported-blue?logo=windows)](#)
[![C++](https://img.shields.io/badge/C%2B%2B-17%2B-blue?logo=cplusplus)](#)
[![Dependency](https://img.shields.io/badge/dependency-Zydis-orange)](https://github.com/zyantific/zydis)



## How It Works Without Allocations

The main feature of `Null-API-Hook` is that it does not require allocating new memory via `VirtualAlloc`, `HeapAlloc`, `malloc`, etc. to store hook data.

Instead, it uses memory that is already present within the loaded PE module.

There is a region between `VirtualSize` and `SizeOfRawData` that can be used to store hook data. The loader maps the section according to `SizeOfRawData`, while the actual size of the section in memory is determined by `VirtualSize`. Therefore, additional space remains, with a size of:

`SizeOfRawData - VirtualSize`

## How It Works

In practice, the hook does not modify the code of the API function itself. Instead, it adds a new link to the function's execution pipeline.

To redirect the call, the `Import Address Table (IAT)` is modified: the address of the original function is replaced with the address of the `Detour`.

For libraries, the `Export Address Table (EAT)` is also modified so that the exported function points to the `Detour`.

Thus, the execution flow looks as follows:

```text
API Call
   │
   ▼
IAT / EAT
   │
   │ Address → Detour
   ▼
Detour
   │
   ▼
Original API
``` 


## Exemple

``` cpp

typedef int (*ProtoMessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);

null::HookState hMessageBoxW{};


int HookMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	std::wcout << L"MessageBoxW: " << lpText << std::endl;

	return ((ProtoMessageBoxW)hMessageBoxW.function.origin)(hWnd, L"Hello from MessageBoxW hook!", lpCaption, uType);
}

int main()
{
    HMODULE hUser32Module = LoadLibraryA("User32.dll");
    null::LibraryState lUser32State{};

    
    if (!null::CreateHook(&lUser32State, &hMessageBoxW, hUser32Module, "MessageBoxW", HookMessageBoxW))
    {
        std::cout << "Error create MessageBoxW hook" << std::endl;
        
        return 0;
    }
}
```

## Build

```
cd third_party\zydis
mkdir build && cd build

cmake ..
cmake --build . --config Release
```

## Dependency
  - [Zydis](https://github.com/zyantific/zydis)
