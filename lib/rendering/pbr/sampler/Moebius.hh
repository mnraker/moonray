// Copyright 2023-2024 DreamWorks Animation LLC
// SPDX-License-Identifier: Apache-2.0


#pragma once

#ifndef RENDERING_PBR_SAMPLER_MOEBIUS_H_
#define RENDERING_PBR_SAMPLER_MOEBIUS_H_

#ifdef ISPC
#include <scene_rdl2/common/platform/Platform.isph>
#define kMoebiusTransformationSize 0x4000u
extern const uniform float moebiusTransformationValues[kMoebiusTransformationSize];
#else
#include <cstdint>
constexpr uint32_t kMoebiusTransformationSize = 0x4000u;
extern "C" const float moebiusTransformationValues[kMoebiusTransformationSize];
#endif

#endif // RENDERING_PBR_SAMPLER_MOEBIUS_H_
