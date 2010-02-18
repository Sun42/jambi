.486
.model flat, stdcall
option casemap:none

.code
start:
; push 5000
; mov eax, 7c802442h
; call   eax

xor eax,eax
mov ebx, 7c802442h ;adresse de Sleep
mov ax, 1337h ;pause durant 4919ms
push eax
call ebx ;Sleep(ms);
end start