#include "hook.h"

namespace null
{
	HookStatus DeleteHook(HookState *state)
	{
		if (!state)
			return NULL_ERROR;

		if (!DisableHook(state))
			return NULL_ERROR;

		std::memset(state->function.hook, 0x0, state->size);

		state->size = 0;
		state->pIAT = nullptr;
		state->pExportRVA = nullptr;

		state->function.detour = nullptr;
		state->function.hook = nullptr;
		state->function.origin = nullptr;

		state->exportRVA = 0;
		state->hookRVA = 0;
		state->procName = nullptr;

		return NULL_SUCCESS;
	}
} // namespace null
