	lea    -128(%rsp), %rsp
	pushf

	cmpl $0xaaaaaaaa, (%rax)
	jne out

lbl:	call lbl

out:
	popf
	lea    128(%rsp), %rsp
