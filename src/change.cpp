#include "hook.h"

namespace null
{

	HookStatus ChangeHook(HookState *state, bool mode)
	{
		if (!state)

			return NULL_ERROR;

		DWORD oldProtect = 0;
		if (!VirtualProtect(state->pExportRVA, sizeof(std::int32_t), PAGE_READWRITE, &oldProtect))
			return NULL_ERROR;

		*((std::int32_t *)state->pExportRVA) = mode ? state->hookRVA : state->exportRVA;

		VirtualProtect(state->pExportRVA, sizeof(std::int32_t), oldProtect, &oldProtect);

		if (state->pIAT)
		{
			if (!VirtualProtect(state->pIAT, sizeof(std::size_t), PAGE_READWRITE, &oldProtect))
				return NULL_ERROR;

			*((std::size_t *)state->pIAT) =
				mode ? (std::size_t)state->function.detour : (std::size_t)state->function.origin;

			VirtualProtect(state->pIAT, sizeof(std::size_t), oldProtect, &oldProtect);
		}
		state->isActive = mode;

		return NULL_SUCCESS;
	}

	HookStatus EnableHook(HookState *state) { return ChangeHook(state, true); }

	HookStatus DisableHook(HookState *state) { return ChangeHook(state, false); }
} // namespace null
