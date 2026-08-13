#include "hook.h"

namespace null
{
	HookStatus DeleteHook(HookState *state)
	{
		if (!state)
			return NULL_ERROR;

		if (!DisableHook(state))
			return NULL_ERROR;

		std::memset(state->function.pHook, 0x0, state->size);
		std::memset(state->iat.arrayIA, 0x0, state->iat.size);

		state->size = 0;
		state->iat.size = 0;
		state->pExportRVA = nullptr;

		state->function.pDetour = nullptr;
		state->function.pHook = nullptr;
		state->function.pOrigin = nullptr;

		state->exportRVA = 0;
		state->hookRVA = 0;
		state->procName = nullptr;

		return NULL_SUCCESS;
	}
} // namespace null
