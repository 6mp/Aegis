#pragma once
#include "../Utils/KUtils.hpp"

namespace NotifyRoutine
{
    auto LoadImage( PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo ) -> void;
}

