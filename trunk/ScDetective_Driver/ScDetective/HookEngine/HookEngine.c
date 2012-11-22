
#include "HookEngine.h"

NTSTATUS OpZwClose(
    __in HANDLE Handle,
    __in PUCHAR OpCodeAddress
    )
{
    NTSTATUS ntStatus;
    pFnZwClose pfnZwClose = (pFnZwClose)OpCodeAddress;
    ntStatus = pfnZwClose(Handle);
    return ntStatus;
}

NTSTATUS fake_ZwClose (
    __in HANDLE Handle
    )
{
    ULONG FunctionId;
    FunctionId = ((ULONG)&fakeAddressTable.pFnZwClose - (ULONG)&fakeAddressTable) / sizeof(ULONG);
    return OpZwClose(Handle, OrigOpCode[FunctionId]);
}

VOID __fastcall fake_KiInsertQueueApc (
    __in PKAPC Apc,
    __in KPRIORITY Increment
    )
{
    ULONG NowThread;
    ULONG NowProcess;
    PUCHAR ProcessName;
    
    NowThread  = *(PULONG)((ULONG)Apc + 8);
    NowProcess = *(PULONG)((ULONG)NowThread + offset_Thread_ThreadsProcess );
    ProcessName = (PUCHAR)((ULONG)NowProcess + offset_Process_ImageFileName);

    if (strstr("ScDetective", (PCHAR)ProcessName) != NULL && Increment == 2)
    {
        return ;
    }
    g_OrigKiInsertQueueApc(Apc, Increment);
}

NTSTATUS fake_ObReferenceObjectByHandle(
    __in HANDLE Handle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_TYPE ObjectType,
    __in KPROCESSOR_MODE AccessMode,
    __out PVOID *Object,
    __out_opt POBJECT_HANDLE_INFORMATION HandleInformation
    )
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    PCHAR ImageFileName;

    ntStatus = ObReferenceObjectByHandle( Handle, 
                                          DesiredAccess, 
                                          ObjectType, 
                                          AccessMode, 
                                          Object, 
                                          HandleInformation);
    if (!NT_SUCCESS(ntStatus)) {
        return ntStatus;
    }
    
    if (DesiredAccess == PROCESS_TERMINATE && ObjectType == *PsProcessType) 
    {
        ImageFileName = (PCHAR)((ULONG)(*Object) + offset_Process_ImageFileName);

        if (_stricmp(ImageFileName, "ScDetective.exe") == 0) 
        {
            KdPrint(("[fake_ObReferenceObjectByHandle] Refused Operate[PROCESS_TERMINATE] %s", ImageFileName));
            ObDereferenceObject(*Object);
            return STATUS_INVALID_HANDLE;
        }
    } 
    else if (DesiredAccess == PROCESS_DUP_HANDLE && ObjectType == *PsProcessType) 
    {
        ImageFileName = (PCHAR)((ULONG)(*Object) + offset_Process_ImageFileName);

        if (_stricmp(ImageFileName, "ScDetective.exe") == 0) 
        {
            KdPrint(("[fake_ObReferenceObjectByHandle] Refused Operate[PROCESS_DUP_HANDLE] %s", ImageFileName));
            ObDereferenceObject(*Object);
            return STATUS_INVALID_HANDLE;
        }
    }   
    return ntStatus;
}

BOOLEAN CheckAddresses(PADDRESS_TABLE TableEntry, ULONG NumberOfAddress)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    BOOLEAN bFlag = 0;
    PSYSTEM_MODULE_INFORMATION Modules;
    PSYSTEM_MODULE_INFORMATION_ENTRY ModuleInfo;
    PVOID Buffer = NULL;
    ULONG BufferSize = 0x2000;
    ULONG ReturnLength;
    ULONG i;
    ULONG Number = 0;
    PULONG Entry = (PULONG)TableEntry;

_Retry:
    Buffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize, MEM_TAG);

    ntStatus = ZwQuerySystemInformation(SystemModuleInformation, 
                                        Buffer,
                                        BufferSize, 
                                        &ReturnLength);

    if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
        BufferSize = ReturnLength;
        ExFreePoolWithTag(Buffer, MEM_TAG);
        goto _Retry;
    }

    if (NT_SUCCESS(ntStatus)) {
        Modules = (PSYSTEM_MODULE_INFORMATION)Buffer;
        ModuleInfo = &(Modules->Modules[0]);

        do {
            if (((ULONG)ModuleInfo->Base + ModuleInfo->Size) < (Entry + Number)[0])  break; 
            Number ++; 
        } while (Number < NumberOfAddress);

        bFlag = TRUE;
    }
    ExFreePoolWithTag(Buffer, MEM_TAG);
    return bFlag;
}

BOOLEAN InitAddress2Hook()
{
    ULONG ServiceId;
    UNICODE_STRING usFuncName;

    if (NumberOfHookedFunction < PREPARE_HOOK_NUMBER) 
    {
        RtlZeroMemory(HookFlags, PREPARE_HOOK_NUMBER);
        NumberOfHookedFunction = PREPARE_HOOK_NUMBER;
    }

    fakeAddressTable.pFnZwOpenKey               =   0;
    fakeAddressTable.pFnZwClose                 =   0; // (ULONG)fake_ZwClose;
    fakeAddressTable.pFnZwQueryValueKey         =   0;
    fakeAddressTable.pFnZwDeleteKey             =   0;
    fakeAddressTable.pFnZwSetValueKey           =   0;
    fakeAddressTable.pFnZwCreateKey             =   
    fakeAddressTable.pFnZwDeleteValueKey        = 
    fakeAddressTable.pFnZwEnumValueKey          =   
    fakeAddressTable.pFnZwRestoreKey            =   
    fakeAddressTable.pFnZwReplaceKey            =   0;
    fakeAddressTable.pFnZwTerminateProcess      =   (ULONG)fake_ObReferenceObjectByHandle;
    fakeAddressTable.pFnZwDuplicateObject       =   (ULONG)fake_ObReferenceObjectByHandle;
    fakeAddressTable.pFnZwSetSystemInformation  = 
    fakeAddressTable.pFnZwCreateThread          =  
    fakeAddressTable.pFnZwTerminateThread       =   0;
    // 替换 KeInsertQueneApc 中的 KiInsertQueneApc
    fakeAddressTable.pFnKeInsertQueneApc        =   (ULONG)fake_KiInsertQueueApc;
           
    OrigAddressTable.pFnZwOpenKey               =   SYSCALL_ADDRESS(ZwOpenKey);
    OrigAddressTable.pFnZwClose                 =   SYSCALL_ADDRESS(ZwClose);
    OrigAddressTable.pFnZwQueryValueKey         =   SYSCALL_ADDRESS(ZwQueryValueKey);
    OrigAddressTable.pFnZwDeleteKey             =   SYSCALL_ADDRESS(ZwDeleteKey);
    OrigAddressTable.pFnZwSetValueKey           =   SYSCALL_ADDRESS(ZwSetValueKey);
    OrigAddressTable.pFnZwCreateKey             =   SYSCALL_ADDRESS(ZwCreateKey);
    OrigAddressTable.pFnZwDeleteValueKey        =   SYSCALL_ADDRESS(ZwDeleteValueKey);
    OrigAddressTable.pFnZwEnumValueKey          =   SYSCALL_ADDRESS(ZwEnumerateValueKey);
    OrigAddressTable.pFnZwRestoreKey            =   SYSCALL_ADDRESS(ZwRestoreKey);
    OrigAddressTable.pFnZwReplaceKey            =   SYSCALL_ADDRESS(ZwReplaceKey);
    OrigAddressTable.pFnZwTerminateProcess      =   SYSCALL_ADDRESS(ZwTerminateProcess);
    OrigAddressTable.pFnZwDuplicateObject       =   SYSCALL_ADDRESS(ZwDuplicateObject);
    OrigAddressTable.pFnZwSetSystemInformation  =   SYSCALL_ADDRESS(ZwSetSystemInformation);

    RtlInitUnicodeString(&usFuncName, L"KeInsertQueueApc");
    OrigAddressTable.pFnKeInsertQueneApc        =   (ULONG)MmGetSystemRoutineAddress(&usFuncName);

    ServiceId = ServiceId_NtCreateThread;
    if (ServiceId) {
        OrigAddressTable.pFnZwCreateThread      =   KeServiceDescriptorTable.ServiceTableBase[ServiceId];
    } else {
        OrigAddressTable.pFnZwCreateThread      =   0;
    } 
    ServiceId = ServiceId_NtTerminateThread;
    if (ServiceId) {
        OrigAddressTable.pFnZwTerminateThread   =   KeServiceDescriptorTable.ServiceTableBase[ServiceId];
    } else {
        OrigAddressTable.pFnZwTerminateThread   =   0;
    }

    return CheckAddresses(&OrigAddressTable, PREPARE_HOOK_NUMBER);
}

BOOLEAN 
xchg_value_hook(ULONG OrigAddress, ULONG fakeAddress, PUCHAR OpCodeMoved, PUCHAR HookFlag, PULONG HookStartAddress, PULONG pcbCoverLength, ULONG Number)
{
    BOOLEAN result = FALSE;
    ULONG OpCodeSize = 0;
    ULONG Length = 0;
    BOOL bFlag = FALSE;
    PUCHAR cPtr;
    PUCHAR pOpCode;
    KIRQL OrigIrql;
    PMDL MdlFuncAddress = NULL;
    ULONG DeltaAddress, OrigDeltaAddress;

    ULONG id_zwtp, id_zwdo, id_kiqa;

    id_zwtp = ((ULONG)&fakeAddressTable.pFnZwTerminateProcess - (ULONG)&fakeAddressTable) / sizeof(ULONG);
    id_zwdo = ((ULONG)&fakeAddressTable.pFnZwDuplicateObject  - (ULONG)&fakeAddressTable) / sizeof(ULONG);
    id_kiqa = ((ULONG)&fakeAddressTable.pFnKeInsertQueneApc   - (ULONG)&fakeAddressTable) / sizeof(ULONG);
    

    if (OrigAddress && fakeAddress && OpCodeMoved && 
        HookFlag && HookStartAddress && pcbCoverLength )
    {
        if (HookFlag[0] == TRUE)  return FALSE;
        
        if (Number == id_zwtp || Number == id_zwdo) 
        {
            for (cPtr  = (PUCHAR)OrigAddress; 
                 cPtr <= (PUCHAR)(OrigAddress + PAGE_SIZE);
                 cPtr  = (PUCHAR)(cPtr + Length))
            {
                Length = SizeOfCode(cPtr, &pOpCode);
                if (Length == 0)  break;

                //
                // 此处的特征码是 : NtTerminateProcess 和 NtDuplicateObject 共用的
                //
                if (*(PUCHAR)cPtr == 0x6A && 
                    *(PULONG)(cPtr + 2) == 0xE80875FF) 
                {
                    HookStartAddress[0] = (ULONG)(cPtr + 6);  
                    OpCodeSize = 4;  bFlag = TRUE;  break;
                }
            }
        }
        
        if (Number == id_kiqa) 
        {
            for (cPtr  = (PUCHAR)OrigAddress; 
                 cPtr <= (PUCHAR)(OrigAddress + PAGE_SIZE);
                 cPtr  = (PUCHAR)(cPtr + Length))
            {
                Length = SizeOfCode(cPtr, &pOpCode);
                if (Length == 0)  break;
                
                //
                // 此处的特征码是寻找 KeInsertQueneApc 中的 KiInsertQueneApc
                // 此处没有考虑安全性，比如此时的 KiInsertQueneApc 已经被替换了，以后完善
                //
                if (*(PUCHAR)cPtr == 0xE8 && 
                    *(PUSHORT)(cPtr + 5) == 0xD88A) 
                {
                    HookStartAddress[0] = (ULONG)(cPtr + 1);  
                    g_OrigKiInsertQueueApc = (pFnKiInsertQueueApc)(*(PULONG)(cPtr + 1) + (ULONG)cPtr + 5);
                    OpCodeSize = 4;  bFlag = TRUE;  break;
                }
            }
        }
        
        if (bFlag == FALSE)  return FALSE;

        if (!ScmMapVirtualAddress((PVOID)OrigAddress, 0x400, &MdlFuncAddress)) return FALSE;

        WPOFF();
        OrigIrql = KeRaiseIrqlToDpcLevel();

        DeltaAddress = fakeAddress - (HookStartAddress[0] - 1) - 5;
        OrigDeltaAddress = InterlockedExchange((PVOID)HookStartAddress[0], DeltaAddress);

        KeLowerIrql(OrigIrql);
        WPON();
        if (OpCodeSize)  HookFlag[0] = TRUE;
        pcbCoverLength[0] = OpCodeSize;

        //
        // 以下判断可以保证 NtTerminateProcess 和 NtDuplicateObject 中的 
        // ObReferenceObjectByHandle 恢复是安全的
        //
        if (Number == id_zwdo || Number == id_zwtp)  
            OrigDeltaAddress = (ULONG)ObReferenceObjectByHandle - (HookStartAddress[0] - 1) - 5;

        RtlCopyMemory(OpCodeMoved, &OrigDeltaAddress, 4);

        ScmUnmapVirtualAddress(MdlFuncAddress);
        result = TRUE;
    }
    return result;
}

ULONG DynamicInlineHook(ULONG TargetAddress, ULONG fakeAddress, PUCHAR OpCodeMoved)
{
    ULONG Length = 0;
    ULONG Result = 0;
    PUCHAR cPtr;
    PUCHAR pOpCode;
    PUCHAR JumpCode;  

    JumpCode = ExAllocatePoolWithTag(NonPagedPool, 16, MEM_TAG);
    JumpCode[0] = 0xE9;

    cPtr = (PUCHAR)TargetAddress;

    while (Length < 5) {
        Length += SizeOfCode(cPtr, &pOpCode);
        cPtr = (PUCHAR)(TargetAddress + Length);
    }

    RtlCopyMemory(OpCodeMoved, (PVOID)TargetAddress, Length);
    ((PULONG)(JumpCode + 1))[0] = (TargetAddress + Length) - ((ULONG)OpCodeMoved + Length) - 5;
    RtlCopyMemory(OpCodeMoved + Length, JumpCode, 5);

    ((PULONG)(JumpCode + 1))[0] = fakeAddress - TargetAddress - 5;

    if (ScHeSafeInlineHook((PVOID)TargetAddress, JumpCode, 5))  Result = Length;
    
    ExFreePoolWithTag(JumpCode, MEM_TAG);
    return Result;
}

BOOLEAN  
OpInlineHook(ULONG OrigAddress, ULONG fakeAddress, PUCHAR OpCodeMoved, 
             PUCHAR HookFlag, PULONG HookStartAddress, PULONG pcbCoverLength)
{
    BOOLEAN result = FALSE;
    ULONG OpCodeSize = 0;

    if (OrigAddress && fakeAddress && OpCodeMoved && 
        HookFlag && HookStartAddress && pcbCoverLength) 
    {
        if (HookFlag[0] == TRUE)  return FALSE;

        OpCodeSize = DynamicInlineHook(OrigAddress, fakeAddress, OpCodeMoved);

        if (OpCodeSize)  HookFlag[0] = TRUE;

        pcbCoverLength[0] = OpCodeSize;
        HookStartAddress[0] = OrigAddress;
        result = TRUE;
    }
    return result;
}

BOOLEAN ScHeInlineHookEngine(ULONG FunctionAddress, ULONG Id)
{
    BOOLEAN result = 0;
    ULONG fakeAddress;
    ULONG id_zwtp, id_zwdo, id_kiqa;

    fakeAddress = *((PULONG)&fakeAddressTable + Id);

    //
    // Id = 5 对应的是 ZwCreateKey
    //
    if (Id == 5)  return result;

    //
    // 如果是 NtTerminateProcess 或者 NtDuplicateObject 
    // 则特殊处理其调用的 ObReferenceObjectByHandle 函数
    //
    id_zwtp = ((ULONG)&fakeAddressTable.pFnZwTerminateProcess - (ULONG)&fakeAddressTable) / sizeof(ULONG);
    id_zwdo = ((ULONG)&fakeAddressTable.pFnZwDuplicateObject  - (ULONG)&fakeAddressTable) / sizeof(ULONG);

    // 
    // 替换 KeInsertQueneApc 中的 KiInsertQueneApc
    //
    id_kiqa = ((ULONG)&fakeAddressTable.pFnKeInsertQueneApc - (ULONG)&fakeAddressTable) / sizeof(ULONG);

    if (Id == id_zwtp || Id == id_zwdo || Id == id_kiqa) {

        return xchg_value_hook(FunctionAddress, fakeAddress, OrigOpCode[Id], 
                    &HookFlags[Id], &CoverStartAddress[Id], &CoverLength[Id], Id);
    }

    result = OpInlineHook(FunctionAddress, fakeAddress, OrigOpCode[Id], 
                    &HookFlags[Id],  &CoverStartAddress[Id], &CoverLength[Id]);

    return result;
}

//////////////////////////////////////////////////////////////////////////

VOID InitilizeHook()
{
    ULONG Number = 0;
    ULONG FuncAddress;

    if (bAlreadyHooked == TRUE)  return ;
    
    memset(HookFlags, 0, PREPARE_HOOK_NUMBER);
    memset(CoverLength, 0, PREPARE_HOOK_NUMBER * 4);
    memset(&OrigAddressTable, 0, sizeof(ADDRESS_TABLE));
    memset(&fakeAddressTable, 0, sizeof(ADDRESS_TABLE));

    if (InitAddress2Hook()) {

        do {
            FuncAddress = ((PULONG)&OrigAddressTable + Number)[0];
            ScHeInlineHookEngine(FuncAddress, Number);
            Number ++;
        } while (Number < PREPARE_HOOK_NUMBER);

        bAlreadyHooked ++;
        // 中间还有个function, 通过 HookFlags 判断是否通过解析 PE(ntoskrnl) 文件解析 ssdt 函数地址
        // 现在先不急着考虑，暂定ssdt表中的函数没有被更改
    }
}

BOOL 
OpUnInlineHook(ULONG OrigAddress, ULONG HookStartAddress, PUCHAR OpCodeMoved, PUCHAR HookFlag, ULONG cbCoverLength)
{
    BOOL result = FALSE;
    ULONG OpCodeSize = 0;


    if (OrigAddress && HookStartAddress && OpCodeMoved && 
        HookFlag && cbCoverLength) 
    {
        if (HookFlag[0] == FALSE)  return TRUE;
        
        result = ScHeSafeInlineHook((PVOID)HookStartAddress, OpCodeMoved, cbCoverLength);

        if (result) 
            HookFlag[0] = FALSE;
        else 
            HookFlag[0] = TRUE;
    }

    return result;
}

BOOL ScHeUnInlineHookEngine(ULONG FunctionAddress, ULONG Id)
{
    BOOL result = FALSE;

    //
    // Id = 5 对应的是 ZwCreateKey
    //
    if (Id == 5)  return result;

    result = OpUnInlineHook(FunctionAddress, CoverStartAddress[Id], 
                        OrigOpCode[Id], &HookFlags[Id], CoverLength[Id]);
                                
    return result;
}

VOID UnInlineHookNativeApi()
{
    ULONG Number = 0;
    ULONG FuncAddress;

    if (bAlreadyHooked) {

        do {
            FuncAddress = ((PULONG)&OrigAddressTable + Number)[0];
            ScHeUnInlineHookEngine(FuncAddress, Number);
            Number ++;
        } while (Number < PREPARE_HOOK_NUMBER);

        bAlreadyHooked --;
    }
}

//////////////////////////////////////////////////////////////////////////

VOID 
OpSafeInlineHook(PVOID TargetAddress, PVOID ReadyOpCode, ULONG OpCodeLength)
{
    PMDL MdlFuncAddress;

    ASSERT(TargetAddress && ReadyOpCode && OpCodeLength);

    if (ScmMapVirtualAddress(TargetAddress, 0x400, &MdlFuncAddress)) 
    {
        WPOFF();
        RtlCopyMemory(TargetAddress, ReadyOpCode, OpCodeLength);
        WPON();
        ScmUnmapVirtualAddress(MdlFuncAddress);
    }
}

VOID SafeHookDpcRoutine (
    __in struct _KDPC *Dpc,
    __in_opt PDPC_CONTEXT DeferredContext,
    __in_opt PVOID SystemArgument1,
    __in_opt PVOID SystemArgument2
    )
{
    InterlockedIncrement(&DeferredContext->LockedProcessors);
    do {
        __asm   pause;
    } while (DeferredContext->ReleaseFlag == FALSE);
    InterlockedDecrement(&DeferredContext->LockedProcessors);
}

BOOL ScHeSafeInlineHook(PVOID TargetAddress, PVOID ReadyOpCode, ULONG OpCodeLength)
{
    BOOL result = FALSE;
    DPC_CONTEXT DpcContext;
    KAFFINITY OrigAffinity;
    UNICODE_STRING NameString;
    CCHAR CurrentProcessor;
    CCHAR Processor;
    PKDPC Dpc;
    ULONG i;
    KIRQL OrigIrql;
    pFnKeSetAffinityThread KeSetAffinityThread = NULL;
    
    RtlInitUnicodeString(&NameString, L"KeSetAffinityThread");
    KeSetAffinityThread = (pFnKeSetAffinityThread)MmGetSystemRoutineAddress(&NameString);

    OrigAffinity = KeSetAffinityThread(KeGetCurrentThread(), 1); 
    OrigIrql = KeRaiseIrqlToDpcLevel();

    if (KeNumberProcessors > 1) {

        CurrentProcessor = (CCHAR)KeGetCurrentProcessorNumber();
        DpcContext.Dpcs = ExAllocatePoolWithTag(NonPagedPool, KeNumberProcessors * sizeof(KDPC), MEM_TAG);
        DpcContext.LockedProcessors = 1;
        DpcContext.ReleaseFlag = FALSE;

        for (Processor = 0; Processor < KeNumberProcessors; Processor++)
        {
            if (Processor == CurrentProcessor)  continue;
            Dpc = &DpcContext.Dpcs[Processor];
            KeInitializeDpc(Dpc, SafeHookDpcRoutine, &DpcContext);
            KeSetTargetProcessorDpc(Dpc, Processor);
            KeInsertQueueDpc(Dpc, NULL, NULL);
        }

        for (i = 0; i < 0x800000; i++) {
            __asm   pause;
            if (DpcContext.LockedProcessors == (ULONG)KeNumberProcessors) break;
        }
        
        if (DpcContext.LockedProcessors != (ULONG)KeNumberProcessors) {
            KdPrint(("[ScSafeInlineHook] Failed to insert dpc to other processors"));
            DpcContext.ReleaseFlag = TRUE;
            for (Processor = 0; Processor < KeNumberProcessors; Processor++) 
            {
                if (Processor != CurrentProcessor) {
                    KeRemoveQueueDpc(&DpcContext.Dpcs[Processor]);
                }
            }
        } else {
            KdPrint(("[ScSafeInlineHook] Insert dpc succeed, now start inline hook"));
            OpSafeInlineHook(TargetAddress, ReadyOpCode, OpCodeLength);
            result = TRUE;
            DpcContext.ReleaseFlag = TRUE;  
        }
        do {
            __asm   pause;
        } while (DpcContext.LockedProcessors != 1);

        ExFreePoolWithTag(DpcContext.Dpcs, MEM_TAG);

    } else {

        OpSafeInlineHook(TargetAddress, ReadyOpCode, OpCodeLength);
        result = TRUE;
    }
    KeLowerIrql(OrigIrql);
    KeSetAffinityThread(KeGetCurrentThread(), OrigAffinity); 
    return result;
}

//////////////////////////////////////////////////////////////////////////
/*
#include <ntddk.h> 
#include "struct.h"



ULONG g_KiInsertQueueApc;
char g_oricode[8];
ULONG g_uCr0;
char *non_paged_memory;
ULONG  g_ProcessNameOffset = 0;


typedef VOID (*KIINSERTQUEUEAPC) (
                                  PKAPC Apc,
                                  KPRIORITY Increment
                                  );
KIINSERTQUEUEAPC KiInsertQueueApc;

typedef void (*DBGPRINT)();
DBGPRINT MyDbgPrint = NULL;


typedef void (*WCSUPR)();
WCSUPR Mywcsupr = NULL;

typedef void (*WCSSTR)();
WCSSTR Mywcsstr = NULL;

CHAR szProtect[] = "SUDAMI";


void WPOFF()
{

    ULONG uAttr;

    _asm
    {
        push eax;
        mov eax, cr0;
        mov uAttr, eax;
        and eax, 0FFFEFFFFh; // CR0 16 BIT = 0
        mov cr0, eax;
        pop eax;
        cli
    };

    g_uCr0 = uAttr; //保存原有的 CRO 屬性

}

VOID WPON()
{

    _asm
    {
        sti
            push eax;
        mov eax, g_uCr0; //恢復原有 CR0 屬性
        mov cr0, eax;
        pop eax;
    };

}

__declspec(naked) __fastcall my_function_detour_KiInsertQueueApc(
    PKAPC Apc,
    KPRIORITY Increment
    )
{
    KAPC*  theApc;
    ULONG  currentThread;
    ULONG  currentProcess;
    PUCHAR currentProcessName;
    int    currentProcessID;
    ULONG    SystemArgument1;
    signed int increment;

    _asm {
        pushad
            pushfd
    }

    _asm {
        nop
            nop
            nop
            nop
            nop
            push ebp
            mov ebp, esp

            sub esp, __LOCAL_SIZE

            mov theApc, ecx
            mov increment, edx

            mov edi, DWORD PTR DbgPrint
            mov MyDbgPrint, edi
    }

    // 得到了当前参数1 -- Apc
    currentThread = *(PULONG)((ULONG)theApc + 8);

    currentProcess = *(PULONG)( (ULONG)currentThread + 0x044 );

    currentProcessName = (PUCHAR)( 0x174 + (ULONG)currentProcess);

    //	SystemArgument1 = *(PULONG)((ULONG)theApc + 0x024);

    //MyDbgPrint( "currentProcess:\t0x%08x\n", (ULONG)currentProcessName );
    //MyDbgPrint( "currentProcess:\t%s\n", currentProcessName );
    //	MyDbgPrint( "PID: %d\n", (int)currentProcessID );

    //__asm add esp, 8
    //	if (strcmp(szProtect, (PCHAR)currentProcessName) == 0 &&
    //		increment == 2 /*&& SystemArgument1 == (ULONG)theApc )
    if ( strstr( szProtect, (PCHAR)currentProcessName ) != NULL &&
        increment == 2 /*&& SystemArgument1 == (ULONG)theApc )
    {
        MyDbgPrint("sudami's Anti-Kill: Fucking...\n");
        __asm {
            add esp,4
                mov esp, ebp
                pop ebp

                popfd
                popad
                ret}
    }

    __asm {

        mov esp, ebp
            pop ebp

            popfd
            popad
    }

    __asm {
        // 实现原函数的前8字节
        mov edi,edi
            push ebp
            mov  ebp, esp
            push ecx
            mov eax,ecx

            //  跳转到原函数中
            _emit 0xEA
            _emit 0xAA
            _emit 0xAA
            _emit 0xAA
            _emit 0xAA
            _emit 0x08
            _emit 0x00
    }
}




ULONG GetFunctionAddr( IN PCWSTR FunctionName)
{
    UNICODE_STRING UniCodeFunctionName;
    RtlInitUnicodeString( &UniCodeFunctionName, FunctionName );
    return (ULONG)MmGetSystemRoutineAddress( &UniCodeFunctionName );   

}

//根据特征值，从KeInsertQueueApc搜索中搜索KiInsertQueueApc
VOID FindKiInsertQueueApcAddress()
{
    PUCHAR cPtr;
    PUCHAR addr;

    addr = (PUCHAR) GetFunctionAddr( L"KeInsertQueueApc" );

    for (cPtr = (PUCHAR)addr; 
        cPtr < (PUCHAR)addr + PAGE_SIZE; 
        cPtr++)
    {
        if (*cPtr == 0xE8 && *(PUSHORT)(cPtr + 5) == 0xD88A) {

            KiInsertQueueApc = (KIINSERTQUEUEAPC)(*(PULONG)(cPtr + 1) + (ULONG)cPtr + 5);
            DbgPrint( "KiInsertQueueApc:\t0x%08x\n", (ULONG)KiInsertQueueApc );
            break;
        }
    }
}



VOID DetourFunctionKiInsertQueueApc()
{

    char *actual_function = (char *)KiInsertQueueApc;
    unsigned long detour_address;
    unsigned long reentry_address;
    KIRQL oldIrql;
    int i = 0;

    char newcode[] = { 0xEA, 0x44, 0x33, 0x22, 0x11, 0x08, 0x00, 0x90 };

    reentry_address = ((unsigned long)KiInsertQueueApc) + 8; 

    non_paged_memory = ExAllocatePool(NonPagedPool, 256);

    for(i=0;i<256;i++)
    {
        ((unsigned char *)non_paged_memory)[i] = ((unsigned char *)my_function_detour_KiInsertQueueApc)[i];
    }

    detour_address = (unsigned long)non_paged_memory;

    *( (unsigned long *)(&newcode[1]) ) = detour_address;

    for(i=0;i<200;i++)
    {
        if( (0xAA == ((unsigned char *)non_paged_memory)[i]) &&
            (0xAA == ((unsigned char *)non_paged_memory)[i+1]) &&
            (0xAA == ((unsigned char *)non_paged_memory)[i+2]) &&
            (0xAA == ((unsigned char *)non_paged_memory)[i+3]))
        {
            *( (unsigned long *)(&non_paged_memory[i]) ) = reentry_address;
            break;
        }
    }


    WPOFF();
    oldIrql = KeRaiseIrqlToDpcLevel();
    for(i=0;i < 8;i++)
    {
        g_oricode[i] = actual_function[i];
        actual_function[i] = newcode[i];
    }
    KeLowerIrql(oldIrql);
    WPON();
}

VOID UnDetourFunction()
{
    char *actual_function = (char *)KiInsertQueueApc;
    KIRQL oldIrql;
    int i = 0;

    WPOFF();
    oldIrql = KeRaiseIrqlToDpcLevel();

    for(i=0;i < 8;i++)
    {
        actual_function[i] = g_oricode[i];
    }
    KeLowerIrql(oldIrql);
    WPON();
    ExFreePool(non_paged_memory);
}

VOID OnUnload( IN PDRIVER_OBJECT DriverObject )
{
    DbgPrint("My Driver Unloaded!");
    UnDetourFunction();
}


NTSTATUS DriverEntry( IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath )
{
    DbgPrint("My Driver Loaded!");
    theDriverObject->DriverUnload = OnUnload;

    FindKiInsertQueueApcAddress();
    if ( NULL == KiInsertQueueApc ) {
        DbgPrint("未找到 KiInsertQueueApc 的地址.");
        return STATUS_UNSUCCESSFUL;
    }

    g_ProcessNameOffset = GetProcessNameOffset();

    if ( 0 == g_ProcessNameOffset ) {
        DbgPrint("g_ProcessNameOffset == NULL, Failed");
        return STATUS_UNSUCCESSFUL;
    } else {
        DbgPrint("g_ProcessNameOffset的便宜：%d\n", (ULONG)g_ProcessNameOffset);
    }


    DetourFunctionKiInsertQueueApc();

    return STATUS_SUCCESS;
}



ULONG  
GetProcessNameOffset( void )
{
    PEPROCESS curproc;
    int i = 0;

    curproc = PsGetCurrentProcess();
    for( i = 0; i < 3*PAGE_SIZE; i++ ) {
        if( !strncmp( "System", (PCHAR)curproc + i, strlen("System") )) {
            return i;
        }
    }

    return 0;
}
*/