_text SEGMENT

__stacker_black_box PROC
    RET
__stacker_black_box ENDP

__stacker_stack_pointer PROC
    MOV RAX, RSP
    RET
__stacker_stack_pointer ENDP

__stacker_switch_stacks PROC
    PUSH RBP
    MOV RBP, RSP
    MOV RSP, RCX            ; switch to our new stack
    MOV RCX, R8             ; move the data pointer to the first argument
    CALL RDX                ; call our function pointer
    MOV RSP, RBP            ; restore the old stack pointer
    POP RBP
    RET
__stacker_switch_stacks ENDP

END
