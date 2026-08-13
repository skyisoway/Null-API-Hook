#include "hook.h"

namespace null
{
	namespace win
	{
		namespace kernelbase
		{
			BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
			{
				return NT_SUCCESS(ntdll::NtProtectVirtualMemory((HANDLE)CURRENT_PROCCESS, &lpAddress, &dwSize,
																flNewProtect, lpflOldProtect));
			}

			PEB *ProcessEnvironmentBlock() { return (PEB *)__readgsqword(0x60); }
		} // namespace kernelbase

	} // namespace win
} // namespace null
