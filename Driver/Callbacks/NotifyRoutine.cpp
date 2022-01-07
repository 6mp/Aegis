#include "NotifyRoutine.hpp"

auto NotifyRoutine::LoadImage( PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo ) -> void
{
    const auto& signature_type = static_cast< SE_IMAGE_SIGNATURE_TYPE >( ImageInfo->ImageSignatureType );
    const auto& signature_level = ImageInfo->ImageSignatureLevel;


    DBG_LOG( "pid %u is loading %ws with ImageSignatureLevel %u and ImageSignatureType %u", ProcessId,
             FullImageName->Buffer, signature_level, signature_type )
}