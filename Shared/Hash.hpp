#pragma once

namespace Hash
{
    //https://handmade.network/forums/t/1507-compile_time_string_hashing_with_c++_constexpr_vs._your_own_preprocessor

    static constexpr auto MK_FNV32_OFFSET_BASIS = 0x811c9dc5;
    static constexpr auto MK_FNV32_PRIME = 16777619;

    __forceinline constexpr auto hash( const char* string )
    {
        unsigned long long hash = MK_FNV32_OFFSET_BASIS;
        while ( *string )
        {
            hash = hash ^ ( unsigned long long )( *string++ );
            hash = hash * MK_FNV32_PRIME;
        }

        return hash;
    }

    __forceinline constexpr auto hash( const wchar_t* string )
    {
        unsigned long long hash = MK_FNV32_OFFSET_BASIS;
        while ( *string )
        {
            hash = hash ^ ( unsigned long long )( *string++ );
            hash = hash * MK_FNV32_PRIME;
        }

        return hash;
    }

    template <unsigned long long hash>
    __forceinline constexpr auto compile_hash()
    {
        return hash;
    }
}

#define COMPILE_HASH( string ) ( Hash::compile_hash<Hash::hash( string )>() )