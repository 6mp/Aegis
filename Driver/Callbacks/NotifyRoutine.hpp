#pragma once
#include "../Utils/Utils.hpp"

namespace NotifyRoutine
{
    auto LoadImage( PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo ) -> void;
}

