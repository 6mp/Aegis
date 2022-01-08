
#include <Windows.h>
#include <filesystem>
#include <iostream>
#include <random>

#include "../Shared/Hash.hpp"
#include "../Shared/Communication.hpp"


int main( char argc, char** argv )
{
    auto device = INVALID_HANDLE_VALUE;
    bool status = FALSE;
    DWORD bytes_returned = 0;

    device =
        CreateFileW( L"\\\\.\\AegisLink", GENERIC_ALL, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, nullptr );

    if ( device == INVALID_HANDLE_VALUE )
    {
        printf_s( "> Could not open device: 0x%x\n", GetLastError() );
        return FALSE;
    }

    {
        const auto current_filename = "SEService.exe";
        std::printf( "current name %s\n", current_filename );

        shared::encryption_key =
            duration_cast<std::chrono::seconds>( std::chrono::system_clock::now().time_since_epoch() ).count();

        shared::Init init{ .requester_name = Hash::hash( current_filename ) };
        std::ranges::generate( init.__pad_1, [ distribution = std::uniform_int_distribution( 0x0, 0xFF ),
                                               random_engine = std::mt19937{ std::random_device{}() } ]() mutable
                               { return distribution( random_engine ); } );

        std::ranges::generate( init.__pad_2, [ distribution = std::uniform_int_distribution( 0x0, 0xFF ),
                                               random_engine = std::mt19937{ std::random_device{}() } ]() mutable
                               { return distribution( random_engine ); } );

        shared::SpinBytes( &init );
        shared::Response response{ .success = false };

        printf_s( "> Issuing IOCTL_INIT 0x%x\n", IOCTL_INIT );
        status = DeviceIoControl( device, IOCTL_INIT, &init, sizeof( shared::Init ), &response,
                                  sizeof( shared::Response ), &bytes_returned, nullptr );
        printf_s( "> IOCTL_INIT 0x%x issued with name %llu\n", IOCTL_INIT, Hash::hash( current_filename ) );

        shared::SpinBytes( &response );
        printf_s( "> Received from the kernel: %u. Received buffer size: %d\n", response.success, bytes_returned );

        getchar();
    }

    {
        shared::Startup start{ .protection_target = COMPILE_HASH( "notepad.exe" ) };
        std::ranges::generate( start.__pad_1, [ distribution = std::uniform_int_distribution( 0x0, 0xFF ),
                                                random_engine = std::mt19937{ std::random_device{}() } ]() mutable
                               { return distribution( random_engine ); } );

        std::ranges::generate( start.__pad_2, [ distribution = std::uniform_int_distribution( 0x0, 0xFF ),
                                                random_engine = std::mt19937{ std::random_device{}() } ]() mutable
                               { return distribution( random_engine ); } );

        shared::SpinBytes( &start );
        shared::Response response{ .success = false };

        printf_s( "> Issuing IOCTL_START 0x%x\n", IOCTL_START );
        status = DeviceIoControl( device, IOCTL_START, &start, sizeof( shared::Startup ), &response,
                                  sizeof( shared::Response ), &bytes_returned, nullptr );
        printf_s( "> IOCTL_START 0x%x issued\n", IOCTL_START );

        shared::SpinBytes( &response );
        printf_s( "> Received from the kernel: %u. Received buffer size: %d\n", response.success, bytes_returned );

        getchar();
    }

    {
        shared::Stop stop{};
        std::ranges::generate( stop.__pad_1, [ distribution = std::uniform_int_distribution( 0x0, 0xFF ),
                                               random_engine = std::mt19937{ std::random_device{}() } ]() mutable
                               { return distribution( random_engine ); } );

        std::ranges::generate( stop.__pad_2, [ distribution = std::uniform_int_distribution( 0x0, 0xFF ),
                                               random_engine = std::mt19937{ std::random_device{}() } ]() mutable
                               { return distribution( random_engine ); } );

        shared::SpinBytes( &stop );
        shared::Response response{ .success = false };

        printf_s( "> Issuing IOCTL_STOP 0x%x\n", IOCTL_STOP );
        status = DeviceIoControl( device, IOCTL_STOP, &stop, sizeof( shared::Stop ), &response,
                                  sizeof( shared::Response ), &bytes_returned, nullptr );
        printf_s( "> IOCTL_STOP 0x%x issued\n", IOCTL_STOP );

        shared::SpinBytes( &response );
        printf_s( "> Received from the kernel: %u. Received buffer size: %d\n", response.success, bytes_returned );

        CloseHandle( device );
        getchar();
    }
}