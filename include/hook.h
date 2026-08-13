#ifndef NULL_HOOK_H
#define NULL_HOOK_H

#define ZYDIS_STATIC_BUILD

#include <Windows.h>
#include <winternl.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <string>

#include <Zydis/Zydis.h>

#ifndef _WIN64
#define MACHINE ZYDIS_MACHINE_MODE_LEGACY_32
#else
#define MACHINE ZYDIS_MACHINE_MODE_LONG_64
#endif

namespace null
{
	struct HookState
	{
		bool isActive = true;

		const char *procName = nullptr;

		struct Function
		{
			void *detour = nullptr;
			void *hook = nullptr;
			void *origin = nullptr;
		} function;

		std::size_t hookRVA = 0;
		std::size_t exportRVA = 0;

		void *pExportRVA = nullptr;
		void *pIAT = nullptr;

		std::size_t size = 0;
	};

	struct LibraryState
	{
		HANDLE hModule = nullptr;

		struct Memory
		{
			void *pStart = nullptr;
			void *pCurrent = nullptr;

			std::size_t size = 0;
		} memory;
	};

	enum HookStatus
	{
		NULL_ERROR,
		NULL_SUCCESS,
	};

	HookStatus CreateHook(_Out_ LibraryState *lState, _Out_ HookState *hState, _In_ HANDLE hModule,
						  _In_ const char *procName, _In_ void *detour);

	HookStatus EnableHook(HookState *state);

	HookStatus DisableHook(HookState *state);

	HookStatus DeleteHook(HookState *state);
} // namespace null

#endif
