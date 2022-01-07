#include "Utils/Utils.hpp"

#include <ntifs.h>

EXTERN_C auto DriverUnload( PDRIVER_OBJECT driver_object ) -> void
{
    UNREFERENCED_PARAMETER( driver_object );

    DBG_LOG( "unload" )
}

EXTERN_C auto DriverEntry( PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path ) -> NTSTATUS
{
    UNREFERENCED_PARAMETER( registry_path );

    DBG_LOG( "in here" )

    driver_object->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}