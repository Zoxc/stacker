#include <stdio.h>
#include <windows.h>
#include <excpt.h>

#ifdef _M_X64
size_t __stacker_get_stack_limit() {
    return __readgsqword(0x1478) + // The base address of the stack. Referenced in GetCurrentThreadStackLimits
           __readgsqword(0x1748) + // The guaranteed pages on a stack overflow. Referenced in SetThreadStackGuarantee
           0x1000; // The guard page
}
#endif

#ifdef _M_IX86
size_t __stacker_get_stack_limit() {
    return __readgsdword(0xE0C) + // The base address of the stack. Referenced in GetCurrentThreadStackLimits
           __readgsdword(0xF78) + // The guaranteed pages on a stack overflow. Referenced in SetThreadStackGuarantee
           0x1000; // The guard page
}
#endif

typedef void (*callback_t)(void *);

struct Info {
    callback_t callback;
    void *data;
    void *old_fiber;
    ULONG stack_guarantee;
    BOOL rethrow;
    DWORD NumberParameters;
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    DWORD ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
};

int filter(unsigned int code, struct _EXCEPTION_POINTERS *ep, struct Info *info) {
    // Don't try to pass noncontinuable exceptions
    if (ep->ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // Ignore all non-C++ exceptions. Rust uses these for "unwinding panics"
    if (ep->ExceptionRecord->ExceptionCode != 0xe06d7363) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    info->ExceptionCode = ep->ExceptionRecord->ExceptionCode;
    info->ExceptionFlags = ep->ExceptionRecord->ExceptionFlags;
    info->NumberParameters = ep->ExceptionRecord->NumberParameters;
    memcpy(&info->ExceptionInformation, &ep->ExceptionRecord->ExceptionInformation, sizeof(DWORD) * info->NumberParameters);
    info->rethrow = TRUE;
    return EXCEPTION_EXECUTE_HANDLER;
}

static VOID CALLBACK fiber_proc(struct Info *info) {
    SetThreadStackGuarantee(&info->stack_guarantee);
    __try {
        info->callback(info->data);
    } __except(filter(GetExceptionCode(), GetExceptionInformation(), info)) {}
    SwitchToFiber(info->old_fiber);
	return;
}

BOOL __stacker_switch_stacks(size_t stack_size, callback_t callback, void *data)
{
    struct Info info;
    info.callback = callback;
    info.data = data;
    info.rethrow = FALSE;
    info.old_fiber = ConvertThreadToFiber(0);
    if (info.old_fiber == NULL)
        return FALSE;
    info.stack_guarantee = 0;
    SetThreadStackGuarantee(&info.stack_guarantee);
    void *fiber = CreateFiber(stack_size, fiber_proc, &info);
    if (fiber == NULL)
        return FALSE;
    SwitchToFiber(fiber);
    DeleteFiber(fiber);
    if (info.rethrow == TRUE) {
        /*RaiseException(info.ExceptionCode,
                       info.ExceptionFlags,
                       info.NumberParameters,
                       &info.ExceptionInformation);*/
                       RaiseException(0xBEEF0000,
                                      0,
                                      0,
                                      0);
    }
    return TRUE;
}