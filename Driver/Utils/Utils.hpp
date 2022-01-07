#pragma once
#include <ntifs.h>
#include "../../Shared/Hash.hpp"


namespace Utils
{
    typedef struct _IMAGE_DOS_HEADER
    {
        USHORT e_magic;
        USHORT e_cblp;
        USHORT e_cp;
        USHORT e_crlc;
        USHORT e_cparhdr;
        USHORT e_minalloc;
        USHORT e_maxalloc;
        USHORT e_ss;
        USHORT e_sp;
        USHORT e_csum;
        USHORT e_ip;
        USHORT e_cs;
        USHORT e_lfarlc;
        USHORT e_ovno;
        USHORT e_res[ 4 ];
        USHORT e_oemid;
        USHORT e_oeminfo;
        USHORT e_res2[ 10 ];
        LONG e_lfanew;
    } IMAGE_DOS_HEADER,* PIMAGE_DOS_HEADER;

    typedef struct _IMAGE_FILE_HEADER
    {
        short Machine;
        short NumberOfSections;
        unsigned TimeDateStamp;
        unsigned PointerToSymbolTable;
        unsigned NumberOfSymbols;
        short SizeOfOptionalHeader;
        short Characteristics;
    } IMAGE_FILE_HEADER,* PIMAGE_FILE_HEADER;

    typedef struct _IMAGE_DATA_DIRECTORY
    {
        unsigned VirtualAddress;
        unsigned Size;
    } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

    typedef struct _IMAGE_OPTIONAL_HEADER64
    {
        short Magic;
        unsigned char MajorLinkerVersion;
        unsigned char MinorLinkerVersion;
        unsigned SizeOfCode;
        unsigned SizeOfInitializedData;
        unsigned SizeOfUninitializedData;
        unsigned AddressOfEntryPoint;
        unsigned BaseOfCode;
        ULONGLONG ImageBase;
        unsigned SectionAlignment;
        unsigned FileAlignment;
        short MajorOperatingSystemVersion;
        short MinorOperatingSystemVersion;
        short MajorImageVersion;
        short MinorImageVersion;
        short MajorSubsystemVersion;
        short MinorSubsystemVersion;
        unsigned Win32VersionValue;
        unsigned SizeOfImage;
        unsigned SizeOfHeaders;
        unsigned CheckSum;
        short Subsystem;
        short DllCharacteristics;
        ULONGLONG SizeOfStackReserve;
        ULONGLONG SizeOfStackCommit;
        ULONGLONG SizeOfHeapReserve;
        ULONGLONG SizeOfHeapCommit;
        unsigned LoaderFlags;
        unsigned NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[ 16 ];
    } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

    typedef struct _IMAGE_NT_HEADERS64
    {
        unsigned Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    } IMAGE_NT_HEADERS64,* PIMAGE_NT_HEADERS64;

    typedef struct _IMAGE_EXPORT_DIRECTORY
    {
        ULONG Characteristics;
        ULONG TimeDateStamp;
        USHORT MajorVersion;
        USHORT MinorVersion;
        ULONG Name;
        ULONG Base;
        ULONG NumberOfFunctions;
        ULONG NumberOfNames;
        ULONG AddressOfFunctions;
        ULONG AddressOfNames;
        ULONG AddressOfNameOrdinals;
    } IMAGE_EXPORT_DIRECTORY,* PIMAGE_EXPORT_DIRECTORY;

    inline PVOID GetKernelBase()
    {
        typedef unsigned char uint8_t;
        auto idt_base = reinterpret_cast<uintptr_t>( KeGetPcr()->IdtBase );
        auto align_page = *reinterpret_cast<uintptr_t*>( idt_base + 4 ) >> 0xc << 0xc;

        for ( ; align_page; align_page -= PAGE_SIZE )
        {
            for ( int index = 0; index < PAGE_SIZE - 0x7; index++ )
            {
                auto current_address = static_cast<intptr_t>( align_page ) + index;

                if ( *reinterpret_cast<uint8_t*>( current_address ) == 0x48 &&
                     *reinterpret_cast<uint8_t*>( current_address + 1 ) == 0x8D &&
                     *reinterpret_cast<uint8_t*>( current_address + 2 ) == 0x1D &&
                     *reinterpret_cast<uint8_t*>( current_address + 6 ) == 0xFF ) // 48 8d 1D ?? ?? ?? FF
                {
                    auto nto_base_offset = *reinterpret_cast<int*>( current_address + 3 );
                    auto nto_base_ = ( current_address + nto_base_offset + 7 );
                    if ( !( nto_base_ & 0xfff ) )
                    {
                        return ( void* )nto_base_;
                    }
                }
            }
        }

        return NULL;
    };

    FORCEINLINE PVOID GetDriverExportByHash( PVOID lpDriverBase, ULONG64 nStrHash )
    {
        auto lpDosHeader = static_cast< PIMAGE_DOS_HEADER >( lpDriverBase );
        auto lpNtHeader = reinterpret_cast< PIMAGE_NT_HEADERS64 >( lpDosHeader->e_lfanew + ( ULONG64 )lpDriverBase );

        PIMAGE_EXPORT_DIRECTORY lpExportDir =
            ( PIMAGE_EXPORT_DIRECTORY )( ( ULONG64 )lpDriverBase +
                                         lpNtHeader->OptionalHeader.DataDirectory[ 0 ]
                                             .VirtualAddress );

        ULONG32* lpNameArr = ( ULONG32* )( lpExportDir->AddressOfNames + ( ULONG64 )lpDriverBase );

        ULONG32* lpFuncs = ( ULONG32* )( lpExportDir->AddressOfFunctions + ( ULONG64 )lpDriverBase );

        USHORT* lpOrdinals = ( USHORT* )( lpExportDir->AddressOfNameOrdinals + ( ULONG64 )lpDriverBase );

        for ( auto nIdx = 0u; nIdx < lpExportDir->NumberOfFunctions; ++nIdx )
        {
            if ( !lpNameArr[ nIdx ] || !lpOrdinals[ nIdx ] )
                continue;

            if ( Hash::hash( ( PCHAR )( ( ULONG64 )lpDriverBase + lpNameArr[ nIdx ] ) ) == nStrHash )
                return ( PVOID )( ( ULONG64 )lpDriverBase + lpFuncs[ lpOrdinals[ nIdx ] ] );
        }
        return NULL;
    }
}


#define DYN_NT_SYM(x)                                   \
  ((decltype(&x))Utils::GetDriverExportByHash(          \
      Utils::GetKernelBase(), COMPILE_HASH( #x ) ) )


#define DBG_LOG( fmt, ... ) \
    DYN_NT_SYM( DbgPrintEx )( DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[oxygen][" __FUNCTION__ "] " fmt "\n", ##__VA_ARGS__ );