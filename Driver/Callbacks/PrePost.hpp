#pragma once
#include "../Utils/KUtils.hpp"

namespace PrePost
{
    inline void* Registration{};
    inline unsigned long long ProcessHash{};

    auto PreCallback( PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation )
        -> OB_PREOP_CALLBACK_STATUS;
    auto PostCallback( PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION pOperationInformation ) -> void;
}