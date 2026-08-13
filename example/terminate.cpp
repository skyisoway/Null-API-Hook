#include "example.h"

typedef void (*ProtoRtlExitUserProcess)(NTSTATUS ExitStatus);

void HookRtlExitUserProcess(NTSTATUS ExitStatus) { std::cout << "HookRtlExitUserProcess: " << ExitStatus << std::endl; }

void Terminate()
{
	HMODULE hModule = GetModuleHandleA("ntdll.dll");

	null::LibraryState lState{};
	null::HookState hState{};

	if (!null::CreateHook(&lState, &hState, hModule, "RtlExitUserProcess", HookRtlExitUserProcess))
	{
		std::cout << "Error create RtlExitUserProcess hook" << std::endl;

		return;
	}
	{
		ProtoRtlExitUserProcess exit = (ProtoRtlExitUserProcess)GetProcAddress(hModule, "RtlExitUserProcess");

		exit(0);
	}
	null::DeleteHook(&hState);
}
