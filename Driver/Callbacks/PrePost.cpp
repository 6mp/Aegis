#include "PrePost.hpp"

#define PROCESS_TERMINATE 0x0001    // TerminateProcess
#define PROCESS_VM_OPERATION 0x0008 // VirtualProtect, WriteProcessMemory
#define PROCESS_VM_READ 0x0010      // ReadProcessMemory
#define PROCESS_VM_WRITE 0x0020     // WriteProcessMemory


UCHAR* PsGetProcessImageFileName( PEPROCESS EProcess );

auto PrePost::PreCallback( PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation )
    -> OB_PREOP_CALLBACK_STATUS
{
    UNREFERENCED_PARAMETER( RegistrationContext );

    const auto name =
        GET_FN( PsGetProcessImageFileName )( static_cast< PEPROCESS >( OperationInformation->Object ) );


    if ( Hash::hash( reinterpret_cast< const char* >( name ) ) == ProcessHash )
    {
        if ( OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE ||
             OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE )
        {
            if ( ( OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess &
                   PROCESS_TERMINATE ) == PROCESS_TERMINATE )
            {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
            }

            if ( ( OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess &
                   PROCESS_VM_READ ) == PROCESS_VM_READ )
            {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
            }

            if ( ( OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess &
                   PROCESS_VM_OPERATION ) == PROCESS_VM_OPERATION )
            {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
            }

            if ( ( OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess &
                   PROCESS_VM_WRITE ) == PROCESS_VM_WRITE )
            {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
            }
        }
    }

    return OB_PREOP_SUCCESS;
}

auto PrePost::PostCallback( PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation ) -> void
{
    UNREFERENCED_PARAMETER( RegistrationContext );
    UNREFERENCED_PARAMETER( OperationInformation );
}