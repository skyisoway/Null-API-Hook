#include "hook.h"

namespace null
{

	std::size_t EncodeHook(_Out_ std::uint8_t *buffer, _In_ void *detour)
	{
		std::uint8_t *start = buffer;

		auto encodeInstructionWithToOperand = [&](std::uint8_t *buffer, ZydisMnemonic mnemomic, ZydisEncoderOperand x,
												  ZydisEncoderOperand y) -> std::size_t
		{
			ZydisEncoderRequest request{};

			request.mnemonic = mnemomic;
			request.operand_count = 2;
			request.operands[0] = x;
			request.operands[1] = y;

			std::size_t lenght = sizeof(request);
			if (ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&request, buffer, &lenght)))
				return lenght;
		};

		auto encodeInstruction = [&](std::uint8_t *buffer, ZydisMnemonic mnemomic,
									 ZydisEncoderOperand operand) -> std::size_t
		{
			ZydisEncoderRequest request{};

			request.mnemonic = mnemomic;
			request.machine_mode = MACHINE;
			if (operand.type)
			{
				request.operand_count = 1;
				request.operands[0] = operand;
			}

			std::size_t lenght = sizeof(request);
			if (ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&request, buffer, &lenght)))
				return lenght;

			return 0;
		};

		{

			/*
				X64:
					SUB RSP, 0x88;
					MOV RAX, DETOUR_FUNCTION;
					CALL RAX;
					ADD  RSP, 0x88;
					RET

				X32:
					MOV RAX, DETOUR_FUNCTION;
					CALL RAX;
					RET

			*/

			ZydisEncoderOperand x{};
			ZydisEncoderOperand y{};

			x.type = ZYDIS_OPERAND_TYPE_REGISTER;
			x.reg.value = MACHINE == ZYDIS_MACHINE_MODE_LONG_64 ? ZYDIS_REGISTER_RAX : ZYDIS_REGISTER_EAX;

			ZydisEncoderOperand rsp{};
			rsp.type = ZYDIS_OPERAND_TYPE_REGISTER;
			rsp.reg.value = MACHINE == ZYDIS_MACHINE_MODE_LONG_64 ? ZYDIS_REGISTER_RSP : ZYDIS_REGISTER_ESP;

			y.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			y.imm.u = (std::size_t)0x88;

			buffer += encodeInstructionWithToOperand(buffer, ZYDIS_MNEMONIC_SUB, rsp, y);

			y.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			y.imm.u = (std::size_t)detour;

			buffer += encodeInstructionWithToOperand(buffer, ZYDIS_MNEMONIC_MOV, x, y);
			buffer += encodeInstruction(buffer, ZYDIS_MNEMONIC_CALL, x);

			y.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			y.imm.u = (std::size_t)0x88;

			buffer += encodeInstructionWithToOperand(buffer, ZYDIS_MNEMONIC_ADD, rsp, y);

			buffer += encodeInstruction(buffer, ZYDIS_MNEMONIC_RET, {});
		}

		return buffer - start;
	}

	void *GetBufferWithAddressByProcName(HANDLE hModule, _In_ const char *procName)
	{
		if (!hModule || !procName)
			return nullptr;

		IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)hModule;
		IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((char *)hModule + dos->e_lfanew);

		IMAGE_DATA_DIRECTORY &dataDirectory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!dataDirectory.VirtualAddress || !dataDirectory.Size)
			return nullptr;

		IMAGE_EXPORT_DIRECTORY *exportDirectory =
			(IMAGE_EXPORT_DIRECTORY *)((char *)hModule + dataDirectory.VirtualAddress);

		std::int32_t *bufferByFunction = (std::int32_t *)((char *)hModule + exportDirectory->AddressOfFunctions);
		std::int32_t *bufferByName = (std::int32_t *)((char *)hModule + exportDirectory->AddressOfNames);
		std::int16_t *bufferByOrdinal = (std::int16_t *)((char *)hModule + exportDirectory->AddressOfNameOrdinals);

		for (std::size_t i = 0; i < exportDirectory->NumberOfFunctions; i++)
		{
			const char *functionName = ((const char *)hModule + bufferByName[i]);
			if (std::strstr(procName, functionName))
				return (void *)&bufferByFunction[bufferByOrdinal[i]];
		}

		return nullptr;
	}

	void SplitIAddressInModule(HookState *state, _In_ void *apiAddress, _In_ void *hook)
	{
		PEB *peb = win::kernelbase::ProcessEnvironmentBlock();

		LIST_ENTRY *first_entry = peb->Ldr->InMemoryOrderModuleList.Flink;
		LDR_DATA_TABLE_ENTRY *table = (LDR_DATA_TABLE_ENTRY *)(first_entry);

		DWORD oldProtect = 0;
		while (first_entry != 0)
		{
			if (!table->FullDllName.Length || !table->FullDllName.Buffer)
				break;

			if (state->iat.size >= NULL_MAX_IAT_MODULE)
				return;

			void *pImageBase = (HMODULE)table->Reserved2[0];

			IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)pImageBase;
			IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((char *)pImageBase + dos->e_lfanew);

			IMAGE_DATA_DIRECTORY dataDirectory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];

			{
				std::size_t *pImport = (std::size_t *)((char *)dos + dataDirectory.VirtualAddress);

				while (dataDirectory.Size)
				{
					if (*pImport == (std::size_t)apiAddress)
					{
						if (!win::kernelbase::VirtualProtect(pImport, sizeof(std::size_t), PAGE_READWRITE, &oldProtect))
							return;

						state->iat.arrayIA[state->iat.size] = pImport;
						state->iat.size++;

						*pImport = (std::size_t)hook;

						win::kernelbase::VirtualProtect(pImport, sizeof(std::size_t), oldProtect, &oldProtect);

						break;
					}

					dataDirectory.Size -= sizeof(std::size_t);
					pImport++;
				}
			}

			first_entry = first_entry->Flink;
			table = (LDR_DATA_TABLE_ENTRY *)(first_entry);
		}
	}

	HookStatus CreateHook(_Out_ LibraryState *lState, _Out_ HookState *hState, _In_ HANDLE hModule,
						  _In_ const char *procName, _In_ void *detour)
	{
		if (!lState || !hState || !hModule || !procName || !detour)
			return NULL_ERROR;

		std::int32_t *bufferWithAddress = (std::int32_t *)GetBufferWithAddressByProcName(hModule, procName);
		if (!bufferWithAddress)
			return NULL_ERROR;

		IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)hModule;
		IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((char *)hModule + dos->e_lfanew);

		IMAGE_SECTION_HEADER *firstSection = IMAGE_FIRST_SECTION(nt);

		DWORD oldProtect = 0;

		if (!lState->memory.pCurrent)
		{

			lState->hModule = hModule;
			lState->memory.pStart = (char *)hModule + (firstSection->VirtualAddress + firstSection->Misc.VirtualSize);
			lState->memory.pCurrent = lState->memory.pStart;
			lState->memory.size = firstSection->SizeOfRawData - firstSection->Misc.VirtualSize;

			if (!win::kernelbase::VirtualProtect(lState->memory.pStart, lState->memory.size, PAGE_EXECUTE_READWRITE,
												 &oldProtect))
				return NULL_ERROR;
		}

		if (!lState->memory.size || lState->memory.size < 100)
		{
			IMAGE_SECTION_HEADER *nextSection = nullptr;
			for (std::size_t i = 0; i < nt->FileHeader.NumberOfSections; i++)
			{
				void *sectionAddress =
					(char *)hModule + firstSection[i].VirtualAddress + firstSection[i].Misc.VirtualSize;

				if (lState->memory.pStart == sectionAddress)
				{
					nextSection = &firstSection[i + 1];
					break;
				}
			}
			if (!nextSection)
				return NULL_ERROR;

			lState->memory.pCurrent = (char *)hModule + nextSection->VirtualAddress + nextSection->Misc.VirtualSize;
			lState->memory.size = nextSection->SizeOfRawData - nextSection->Misc.VirtualSize;

			if (!win::kernelbase::VirtualProtect(lState->memory.pStart, lState->memory.size, PAGE_EXECUTE_READWRITE,
												 &oldProtect))
				return NULL_ERROR;
		}

		hState->procName = procName;

		hState->function.pDetour = detour;
		hState->function.pHook = lState->memory.pCurrent;
		hState->function.pOrigin = (char *)hModule + *bufferWithAddress;

		hState->hookRVA = ((std::size_t)lState->memory.pCurrent - (std::size_t)hModule);
		hState->exportRVA = *bufferWithAddress;

		hState->pExportRVA = bufferWithAddress;

		// GET FUNCTION IN IAT
		{
			SplitIAddressInModule(hState, hState->function.pOrigin, hState->function.pHook);
		}

		{
			if (!win::kernelbase::VirtualProtect(bufferWithAddress, sizeof(std::int32_t), PAGE_READWRITE, &oldProtect))
				return NULL_ERROR;
			*bufferWithAddress = ((std::size_t)lState->memory.pCurrent - (std::size_t)lState->hModule);

			win::kernelbase::VirtualProtect(bufferWithAddress, sizeof(std::int32_t), oldProtect, &oldProtect);
		}

		std::size_t encodeSize = EncodeHook((std::uint8_t *)lState->memory.pCurrent, detour);
		{
			lState->memory.pCurrent = (void *)((char *)lState->memory.pCurrent + encodeSize);
			lState->memory.size -= encodeSize;

			hState->size = encodeSize;
		}

		return NULL_SUCCESS;
	}
} // namespace null
