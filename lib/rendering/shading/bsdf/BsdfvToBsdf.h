// Copyright 2023-2024 DreamWorks Animation LLC
// SPDX-License-Identifier: Apache-2.0

/// @file BsdfvToBsdf.h
#pragma once

#ifndef RENDERING_SHADING_BSDF_BSDFVTOBSDF_H_
#define RENDERING_SHADING_BSDF_BSDFVTOBSDF_H_

#include "Bsdf.h"

namespace moonray {
namespace shading {

/// Convert one lane of a Bsdfv into a scalar Bsdf.
void BsdfvToBsdf(const Bsdfv *bsdfv, const int lane,
                 Bsdf *bsdf, alloc::Arena &arena);

Bsdf *BsdfvToBsdf(unsigned numBlocks, const Bsdfv *bsdfv,
                  unsigned numEntries, alloc::Arena *arena);

} // shading
} // moonray

#endif // RENDERING_SHADING_BSDF_BSDFVTOBSDF_H_
