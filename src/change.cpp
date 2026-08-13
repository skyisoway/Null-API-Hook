#include "hook.h"

namespace null
{

	HookStatus ChangeHook(HookState *state, bool mode)
	{
		if (!state)
			return NULL_ERROR;

		DWORD oldProtect = 0;
		if (!win::kernelbase::VirtualProtect(state->pExportRVA, sizeof(std::int32_t), PAGE_READWRITE, &oldProtect))
			return NULL_ERROR;

		*((std::int32_t *)state->pExportRVA) = mode ? state->hookRVA : state->exportRVA;

		win::kernelbase::VirtualProtect(state->pExportRVA, sizeof(std::int32_t), oldProtect, &oldProtect);

		std::int16_t size = state->iat.size;
		do
		{
			if (!win::kernelbase::VirtualProtect(state->iat.arrayIA[size - 1], sizeof(std::size_t), PAGE_READWRITE,
												 &oldProtect))
				return NULL_ERROR;

			*((std::size_t *)state->iat.arrayIA[size - 1]) =
				mode ? (std::size_t)state->function.pDetour : (std::size_t)state->function.pOrigin;

			win::kernelbase::VirtualProtect(state->iat.arrayIA[size - 1], sizeof(std::size_t), oldProtect, &oldProtect);

			size--;
		} while (size);

		state->isActive = mode;

		return NULL_SUCCESS;
	}

	HookStatus EnableHook(HookState *state) { return ChangeHook(state, true); }

	HookStatus DisableHook(HookState *state) { return ChangeHook(state, false); }
} // namespace null
