.code


NtProtectVirtualMemory PROC
    mov r10, rcx
    mov rax, 50h
    syscall
    ret
NtProtectVirtualMemory ENDP


END