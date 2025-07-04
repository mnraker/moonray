// Copyright 2023-2024 DreamWorks Animation LLC
// SPDX-License-Identifier: Apache-2.0

#if !defined(__APPLE__) && !defined(_MSC_VER)

#include "CPUID.h"

namespace moonray {
namespace util {


std::string CPUID::s_vendor;
cpuid_detail::CPUFeatures CPUID::s_features = cpuid_detail::CPUFeatures::NONE;
CPUID::AtomicSize CPUID::s_atomic_sizes;

} // namespace util
} // namespace moonray

#endif
