#include "NotifyRoutine.hpp"

auto NotifyRoutine::LoadImage( PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo ) -> void
{
    const auto& signature_type = static_cast< SE_IMAGE_SIGNATURE_TYPE >( ImageInfo->ImageSignatureType );
    const auto& signature_level = ImageInfo->ImageSignatureLevel;

    // https://shhoya.github.io/antikernel_processprotect2.html

    DBG_LOG( "pid %u is loading %ws with ImageSignatureLevel %u and ImageSignatureType %u", ProcessId,
             FullImageName->Buffer, signature_level, signature_type )



    if ( !ProcessId && FullImageName && DYN_NT_SYM( wcsstr )( FullImageName->Buffer, L"dbk.sys" ) )
    {
        *reinterpret_cast< std::nullptr_t* >( 0 ) = 0;
    }
}