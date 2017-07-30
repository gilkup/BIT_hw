lea    -128(%rsp), %rsp
push   %rbp
mov    %rsp,%rbp
pushf
push   %rdi
push   %rsi
push   %rdx
push   %rcx
push   %r8
push   %r9
push   %r10
push   %r11
push   %rax

lbl: call lbl

pop    %rax
pop    %r11
pop    %r10
pop    %r9
pop    %r8
pop    %rcx
pop    %rdx
pop    %rsi
pop    %rdi
popf
leave

lea    128(%rsp), %rsp

