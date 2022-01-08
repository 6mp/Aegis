#pragma once
#include <ntifs.h>
#include "../../Shared/Hash.hpp"



#define GET_SYM( x ) Utils::GetExportByHash( Utils::GetBase(), COMPILE_HASH( x ) )

#define GET_FN( x ) static_cast<decltype( &x )>( Utils::GetExportByHash( Utils::GetBase(), COMPILE_HASH( #x ) ) )

#ifdef _DEBUG
#define DBG_LOG( fmt, ... )                                                                                            \
    GET_FN( DbgPrintEx )                                                                                               \
    ( DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[6mp][" __FUNCTION__ "] " fmt "\n", ##__VA_ARGS__ );
#endif

#ifndef _DEBUG
#define DBG_LOG( fmt, ... )                                                                                            
#endif

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

    typedef struct _SYSTEM_THREAD
    {
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER CreateTime;
        ULONG WaitTime;
        PVOID StartAddress;
        CLIENT_ID ClientId;
        KPRIORITY Priority;
        LONG BasePriority;
        ULONG ContextSwitchCount;
        ULONG State;
        KWAIT_REASON WaitReason;
    } SYSTEM_THREAD, *PSYSTEM_THREAD;

    typedef struct _SYSTEM_PROCESS_INFORMATION
    {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        LARGE_INTEGER Reserved[ 3 ];
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ImageName;
        KPRIORITY BasePriority;
        HANDLE ProcessId;
        HANDLE InheritedFromProcessId;
        ULONG HandleCount;
        ULONG Reserved2[ 2 ];
        ULONG PrivatePageCount;
        VM_COUNTERS VirtualMemoryCounters;
        IO_COUNTERS IoCounters;
        SYSTEM_THREAD Threads[ 0 ];
    } SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

    typedef struct _RTL_PROCESS_MODULE_INFORMATION
    {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[ 256 ];
    } RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

    typedef struct _RTL_PROCESS_MODULES
    {
        ULONG NumberOfModules;
        RTL_PROCESS_MODULE_INFORMATION Modules[ 1 ];
    } RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

    typedef enum _SYSTEM_INFORMATION_CLASS
    {
        SystemBasicInformation,
        SystemProcessorInformation,
        SystemPerformanceInformation,
        SystemTimeOfDayInformation,
        SystemPathInformation,
        SystemProcessInformation,
        SystemCallCountInformation,
        SystemDeviceInformation,
        SystemProcessorPerformanceInformation,
        SystemFlagsInformation,
        SystemCallTimeInformation,
        SystemModuleInformation,
        SystemLocksInformation,
        SystemStackTraceInformation,
        SystemPagedPoolInformation,
        SystemNonPagedPoolInformation,
        SystemHandleInformation,
        SystemObjectInformation,
        SystemPageFileInformation,
        SystemVdmInstemulInformation,
        SystemVdmBopInformation,
        SystemFileCacheInformation,
        SystemPoolTagInformation,
        SystemInterruptInformation,
        SystemDpcBehaviorInformation,
        SystemFullMemoryInformation,
        SystemLoadGdiDriverInformation,
        SystemUnloadGdiDriverInformation,
        SystemTimeAdjustmentInformation,
        SystemSummaryMemoryInformation,
        SystemNextEventIdInformation,
        SystemEventIdsInformation,
        SystemCrashDumpInformation,
        SystemExceptionInformation,
        SystemCrashDumpStateInformation,
        SystemKernelDebuggerInformation,
        SystemContextSwitchInformation,
        SystemRegistryQuotaInformation,
        SystemExtendServiceTableInformation,
        SystemPrioritySeperation,
        SystemPlugPlayBusInformation,
        SystemDockInformation
    } SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

    typedef struct _KLDR_DATA_TABLE_ENTRY
    {
        struct _LIST_ENTRY InLoadOrderLinks;             // 0x0
        VOID* ExceptionTable;                            // 0x10
        ULONG ExceptionTableSize;                        // 0x18
        VOID* GpValue;                                   // 0x20
        struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo; // 0x28
        VOID* DllBase;                                   // 0x30
        VOID* EntryPoint;                                // 0x38
        ULONG SizeOfImage;                               // 0x40
        struct _UNICODE_STRING FullDllName;              // 0x48
        struct _UNICODE_STRING BaseDllName;              // 0x58
        ULONG Flags;                                     // 0x68
        USHORT LoadCount;                                // 0x6c
        union
        {
            USHORT SignatureLevel : 4; // 0x6e
            USHORT SignatureType : 3;  // 0x6e
            USHORT Unused : 9;         // 0x6e
            USHORT EntireField;        // 0x6e
        } u1;                          // 0x6e
        VOID* SectionPointer;          // 0x70
        ULONG CheckSum;                // 0x78
        ULONG CoverageSectionSize;     // 0x7c
        VOID* CoverageSection;         // 0x80
        VOID* LoadedImports;           // 0x88
        VOID* Spare;                   // 0x90
        ULONG SizeOfImageNotRounded;   // 0x98
        ULONG TimeDateStamp;           // 0x9c
    } KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY; 


    NTSTATUS ZwQuerySystemInformation( SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                                  PVOID SystemInformation, ULONG SystemInformationLength,
                                                  PULONG ReturnLength );

    FORCEINLINE PVOID GetBase()
    {
        static void* base;
        if ( base == nullptr )
        {
            const auto idt_base = reinterpret_cast<ULONG64>( KeGetPcr()->IdtBase );

            for ( auto align_page = *reinterpret_cast<ULONG64*>( idt_base + 4 ) >> 0xc << 0xc; align_page;
                  align_page -= PAGE_SIZE )
            {
                for ( int index = 0; index < PAGE_SIZE - 0x7; index++ )
                {
                    const auto current_address = static_cast<intptr_t>( align_page ) + index;

                    if ( *reinterpret_cast<UINT8*>( current_address ) == 0x48 &&
                         *reinterpret_cast<UINT8*>( current_address + 1 ) == 0x8D &&
                         *reinterpret_cast<UINT8*>( current_address + 2 ) == 0x1D &&
                         *reinterpret_cast<UINT8*>( current_address + 6 ) == 0xFF ) // 48 8d 1D ?? ?? ?? FF
                    {
                        const auto nto_base_offset = *reinterpret_cast<int*>( current_address + 3 );
                        if (auto nto_base_ = ( current_address + nto_base_offset + 7 ); !( nto_base_ & 0xfff ) )
                        {
                            base = reinterpret_cast<void*>( nto_base_ );
                            return base;
                        }
                    }
                }
            }

            return nullptr;
        }

        return base;
    };

    FORCEINLINE PVOID GetExportByHash( void* driver_base, ULONG64 hash )
    {
        const auto dos_header = static_cast<PIMAGE_DOS_HEADER>( driver_base );
        const auto nt_header =
            reinterpret_cast<PIMAGE_NT_HEADERS64>( dos_header->e_lfanew + reinterpret_cast<ULONG64>( driver_base ) );

        const auto export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
            reinterpret_cast<ULONG64>( driver_base ) + nt_header->OptionalHeader.DataDirectory[ 0 ].VirtualAddress );

        const auto names =
            reinterpret_cast<ULONG32*>( export_dir->AddressOfNames + reinterpret_cast<ULONG64>( driver_base ) );

        const auto functions =
            reinterpret_cast<ULONG32*>( export_dir->AddressOfFunctions + reinterpret_cast<ULONG64>( driver_base ) );

        const auto ordinals =
            reinterpret_cast<USHORT*>( export_dir->AddressOfNameOrdinals + reinterpret_cast<ULONG64>( driver_base ) );

        for ( auto idx{ 0u }; idx < export_dir->NumberOfFunctions; ++idx )
        {
            if ( !names[ idx ] || !ordinals[ idx ] )
                continue;

            if ( Hash::hash( reinterpret_cast<PCHAR>( reinterpret_cast<ULONG64>( driver_base ) + names[ idx ] ) ) ==
                 hash )
                return reinterpret_cast<PVOID>( reinterpret_cast<ULONG64>( driver_base ) +
                                                functions[ ordinals[ idx ] ] );
        }
        return nullptr;
    }

    FORCEINLINE HANDLE GetPidByHash( const ULONG64 hash )
    {
        ULONG alloc_size{};
        GET_FN( ZwQuerySystemInformation )
        ( SystemProcessInformation, nullptr, alloc_size, &alloc_size );

        auto procInfo =
            static_cast<PSYSTEM_PROCESS_INFORMATION>( GET_FN( ExAllocatePool )( NonPagedPool, alloc_size ) );

        const auto origPtr = procInfo;
        GET_FN( ZwQuerySystemInformation )
        ( SystemProcessInformation, procInfo, alloc_size, &alloc_size );

        while ( true )
        {
            if ( procInfo->ImageName.Buffer )
            {
                if ( Hash::hash( procInfo->ImageName.Buffer ) == hash )
                {
                    const auto result = procInfo->ProcessId;
                    GET_FN( ExFreePool )( origPtr );
                    return result;
                }
            }

            if ( !procInfo->NextEntryOffset )
                break;

            procInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>( reinterpret_cast<ULONG64>( procInfo ) +
                                                                      procInfo->NextEntryOffset );
        }

        GET_FN( ExFreePool )( origPtr );
        return nullptr;
    }
}
