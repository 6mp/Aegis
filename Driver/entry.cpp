#include "Utils/Utils.hpp"
#include "Callbacks/NotifyRoutine.hpp"
#include "Callbacks/PrePost.hpp"
#include "../Shared/Communication.hpp"


UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING( L"\\Device\\Aegis" );
UNICODE_STRING DEVICE_SYMBOLIC_NAME = RTL_CONSTANT_STRING( L"\\??\\AegisLink" );

EXTERN_C auto DriverUnload( PDRIVER_OBJECT driver_object ) -> void
{
    UNREFERENCED_PARAMETER( driver_object );
    DBG_LOG( "Driver unloaded" )
    GET_FN( IoDeleteDevice )( driver_object->DeviceObject );
    GET_FN( IoDeleteSymbolicLink )( &DEVICE_SYMBOLIC_NAME );
}

EXTERN_C auto IoctlHandler( PDEVICE_OBJECT device_object, PIRP irp ) -> NTSTATUS
{
    UNREFERENCED_PARAMETER( device_object );
    const auto stack_location = IoGetCurrentIrpStackLocation( irp );

    switch ( stack_location->Parameters.DeviceIoControl.IoControlCode )
    {
        case IOCTL_INIT:
        {
            //seconds for epoch, used for encryption key
            LARGE_INTEGER time{};
            ULONG kernelmode_time{};
            GET_FN( KeQuerySystemTimePrecise )( &time );
            GET_FN( RtlTimeToSecondsSince1970 )( &time, &kernelmode_time );
            shared::encryption_key = kernelmode_time;

            //decrypt ioctl buffer
            shared::Init init{};
            RtlCopyMemory( &init, irp->AssociatedIrp.SystemBuffer, sizeof( shared::Init ) );
            shared::SpinBytes( &init, sizeof( shared::Init ) );
            const auto requester_name = init.requester_name;
            DBG_LOG( "requester_name, %llu", requester_name );

            //make sure request is coming from one of our procees, TODO: improve
            if ( requester_name != COMPILE_HASH( "Client.exe" ) )
            {
                shared::Response response{ .success = false };
                shared::SpinBytes( &response );

                RtlCopyMemory( irp->AssociatedIrp.SystemBuffer, &response, sizeof( shared::Response ) );
                irp->IoStatus.Information = sizeof( shared::Response );
                irp->IoStatus.Status = STATUS_DUPLICATE_NAME;
                break;
            }
    

            //prepare response and encrypt
            shared::Response response{ .success = true };
            shared::SpinBytes( &response );

            RtlCopyMemory( irp->AssociatedIrp.SystemBuffer, &response, sizeof( shared::Response ) );
            irp->IoStatus.Information = sizeof( shared::Response );
            irp->IoStatus.Status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_START:
        {
            shared::SpinBytes( irp->AssociatedIrp.SystemBuffer, sizeof( shared::Startup ) );
            PrePost::ProcessHash = static_cast<shared::Startup*>( irp->AssociatedIrp.SystemBuffer )->protection_target;
            shared::SpinBytes( irp->AssociatedIrp.SystemBuffer, sizeof( shared::Startup ) );

            OB_CALLBACK_REGISTRATION obr{};
            // ReSharper disable once CppInitializedValueIsAlwaysRewritten
            OB_OPERATION_REGISTRATION ocr{};

            obr.Version = GET_FN( ObGetFilterVersion )();
            obr.OperationRegistrationCount = 1;
            GET_FN( RtlInitUnicodeString )( &obr.Altitude, L"300000" );
            obr.RegistrationContext = nullptr;

            ocr.ObjectType = static_cast<POBJECT_TYPE*>( GET_SYM( "PsProcessType" ) );
            ocr.Operations = OB_OPERATION_HANDLE_CREATE;
            ocr.PreOperation = PrePost::PreCallback;
            ocr.PostOperation = PrePost::PostCallback;

            obr.OperationRegistration = &ocr;

            //register callbacks
            const auto callback_reg_status = GET_FN( ObRegisterCallbacks )( &obr, &PrePost::Registration );
            const auto load_image_status = GET_FN( PsSetLoadImageNotifyRoutine )( NotifyRoutine::LoadImage );


            shared::Response response{ .success = callback_reg_status == STATUS_SUCCESS && load_image_status == STATUS_SUCCESS };
            shared::SpinBytes( &response );

            RtlCopyMemory( irp->AssociatedIrp.SystemBuffer, &response, sizeof( shared::Response ) );
            irp->IoStatus.Information = sizeof( shared::Response );
            irp->IoStatus.Status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_STOP:
        {
            shared::SpinBytes( irp->AssociatedIrp.SystemBuffer, sizeof( shared::Stop ) );

            shared::SpinBytes( irp->AssociatedIrp.SystemBuffer, sizeof( shared::Stop ) );

            auto pid = Utils::GetPidByHash( PrePost::ProcessHash );
            HANDLE process_handle;
            CLIENT_ID client_id{ .UniqueProcess = pid, .UniqueThread = nullptr };
            OBJECT_ATTRIBUTES obj_attr{};

            //terminate the process for cleanup
            auto status = GET_FN( ZwOpenProcess )( &process_handle, PROCESS_ALL_ACCESS, &obj_attr, &client_id );
            status = GET_FN( ZwTerminateProcess )( process_handle, 0 );
            status = GET_FN( PsRemoveLoadImageNotifyRoutine )( NotifyRoutine::LoadImage );
            GET_FN( ObUnRegisterCallbacks )( PrePost::Registration );

            shared::Response response{ .success = status == STATUS_SUCCESS };
            shared::SpinBytes( &response );

            RtlCopyMemory( irp->AssociatedIrp.SystemBuffer, &response, sizeof( shared::Response ) );
            irp->IoStatus.Information = sizeof( shared::Response );
            irp->IoStatus.Status = STATUS_SUCCESS;
            break;
        }
            DEFAULT_UNREACHABLE;
    }

    GET_FN( IofCompleteRequest )( irp, IO_NO_INCREMENT );

    return STATUS_SUCCESS;
}

EXTERN_C auto CreateClose( PDEVICE_OBJECT device_object, PIRP irp ) -> NTSTATUS
{
    UNREFERENCED_PARAMETER( device_object );

    auto stack_location = IoGetCurrentIrpStackLocation( irp );

    irp->IoStatus.Information = 0;
    irp->IoStatus.Status = STATUS_SUCCESS;
    GET_FN( IofCompleteRequest )( irp, IO_NO_INCREMENT );

    return STATUS_SUCCESS;
}

EXTERN_C auto DriverEntry( PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path ) -> NTSTATUS
{
    UNREFERENCED_PARAMETER( registry_path );

    //Needed to register callbacks
    static_cast<Utils::PKLDR_DATA_TABLE_ENTRY>( driver_object->DriverSection )->Flags |= 32;

    if ( !static_cast<PBOOLEAN>( GET_SYM( "KdDebuggerNotPresent" ) ) ||
                                 static_cast<PBOOLEAN>( GET_SYM( "KdDebuggerEnabled" ) ) )
    {
        //This would be checked in the driver loader
        return STATUS_ABANDONED;
    }

    driver_object->DriverUnload = DriverUnload;
    driver_object->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = IoctlHandler;
    driver_object->MajorFunction[ IRP_MJ_CREATE ] = CreateClose;
    driver_object->MajorFunction[ IRP_MJ_CLOSE ] = CreateClose;

    DBG_LOG( "Driver loaded" )

    GET_FN( IoCreateDevice )
    ( driver_object, 0, &DEVICE_NAME, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &driver_object->DeviceObject );

    return GET_FN( IoCreateSymbolicLink )( &DEVICE_SYMBOLIC_NAME, &DEVICE_NAME );
}