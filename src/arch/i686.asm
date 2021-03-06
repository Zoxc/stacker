.586
.MODEL FLAT, C
.CODE

__stacker_black_box PROC
    RET
__stacker_black_box ENDP

__stacker_stack_pointer PROC
    MOV EAX, ESP
    RET
__stacker_stack_pointer ENDP

__stacker_get_tib_32 PROC
    ASSUME FS:NOTHING
    MOV EAX, FS:[24]
    ASSUME FS:ERROR
    RET
__stacker_get_tib_32 ENDP

__stacker_switch_stacks PROC
    PUSH EBP
    MOV EBP, ESP
    MOV ESP, [EBP + 8]      ; switch stacks
    MOV EAX, [EBP + 12]     ; load the function we're going to call
    PUSH [EBP + 16]         ; push the argument to this function
    CALL EAX                ; call the next function
    MOV ESP, EBP            ; restore the old stack pointer
    POP EBP
    RET
__stacker_switch_stacks ENDP

END
