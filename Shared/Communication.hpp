#pragma once

namespace shared
{
    __declspec( align( 8 ) ) struct Init
    {
        char __pad_1[ 57 ]{};
        unsigned long long requester_name{};
        char __pad_2[ 71 ]{};
    };
    static_assert( sizeof( Init ) == 144 && sizeof( Init ) % 8 == 0 );

    __declspec( align( 8 ) ) struct Startup
    {
        char __pad_1[ 74 ]{};
        unsigned long long protection_target{};
        char __pad_2[ 38 ]{};
    };
    static_assert( sizeof( Startup ) == 128 && sizeof( Init ) % 8 == 0 );

    __declspec( align( 8 ) ) struct Stop
    {
        char __pad_1[ 74 ]{};
        char __pad_2[ 54 ]{};
    };

    struct Response
    {
        bool success;
    };

    inline long long encryption_key{};

    template <typename Ty>
    __forceinline auto SpinBytes( Ty* packet, const __int64 size = sizeof( Ty ) )
    {
        for ( auto idx{ 0ll }; idx < size; ++idx )
        {
            reinterpret_cast<unsigned char*>( packet )[ idx ] ^= static_cast<UINT8>( encryption_key );
        }
    }

#define IOCTL_INIT CTL_CODE( FILE_DEVICE_UNKNOWN, 0x997, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_START CTL_CODE( FILE_DEVICE_UNKNOWN, 0x998, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_STOP CTL_CODE( FILE_DEVICE_UNKNOWN, 0x999, METHOD_BUFFERED, FILE_ANY_ACCESS )
} // namespace shared
