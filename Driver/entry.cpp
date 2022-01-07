#include <ntifs.h>

EXTERN_C auto DriverUnload( PDRIVER_OBJECT driver_object ) -> void
{
    UNREFERENCED_PARAMETER( driver_object );
}

EXTERN_C auto DriverEntry( PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path ) -> NTSTATUS
{
    UNREFERENCED_PARAMETER( registry_path );

    driver_object->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}