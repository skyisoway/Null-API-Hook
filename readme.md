# Null-API-Hook
[![Windows](https://img.shields.io/badge/Windows-supported-blue?logo=windows)](#)
[![C++](https://img.shields.io/badge/C%2B%2B-17%2B-blue?logo=cplusplus)](#)
[![Dependency](https://img.shields.io/badge/dependency-Zydis-orange)](https://github.com/zyantific/zydis)


## Как работает без аллокаций

Главная особенность `Null-API-Hook` - для размещения данных hook не требуется выделять новую память через `VirtualAlloc`, `HeapAlloc`, `malloc` и тд.
Вместо этого использует память, которая уже присутствует в загруженном PE-модуле.

Между `VirtualSize` и `SizeOfRawData` остаётся область, которую можно использовать для размещения данных hook. Загрузчик отображает секцию с учётом `SizeOfRawData`, в то время как фактически используемый размер секции определяется `VirtualSize`. Поэтому остается дополнительное пространство размером: `SizeOfRawData - VirtualSize`


## Принцип работы

Фактически hook не модифицирует код самой API-функции. Вместо этого он добавляет новое звено в pipeline выполнения функции.

Для перенаправления вызова модифицируется `Import Address Table (IAT)`: адрес исходной функции заменяется на адрес `Detour`.
Для библиотек также модифицируется `Export Address Table (EAT)`, чтобы экспортируемая функция указывала на `Detour`.

Таким образом, схема выполнения выглядит следующим образом:

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

## Используемые вызовы

Во время установки и работы hook используются следующие функции:

```text
Windows API
    VirtualProtect
    GetModuleHandleA

LIB
  memset
  strstr
```

## Dependency
  - [Zydis](https://github.com/zyantific/zydis)
