;   Driver Model 2012
;   Filename: Amd64Funcs.asm
;	Last revision: dd/mm/2012
TITLE Driver Model AMD64 Assembler file

;Declare an external function
;EXTERN ExternalCFunc: PROC

.data

.code
; BOOLEAN InvokeCpuid(DWORD Index, LPVOID * lpCpuIdContext)
InvokeCpuid PROC
	MOV R8, RDX
	MOV RAX, RCX
	CPUID

	; Save the context
	TEST R8, R8
	JZ NoCtx
	MOV DWORD PTR [R8], EAX
	MOV DWORD PTR [R8+04], EAX
	MOV DWORD PTR [R8+08], EAX
	MOV DWORD PTR [R8+0Ch], EAX
	
	XOR EAX, EAX
	INC EAX

NoCtx:
	RET
InvokeCpuid ENDP

END