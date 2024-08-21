// Copyright 2023-2024 DreamWorks Animation LLC
// SPDX-License-Identifier: Apache-2.0

/// @file Event.hh

#pragma once

#define LPE_EVENT_TYPE_ENUMS(NS)            \
    NS##_TYPE_NONE,                         \
    NS##_TYPE_CAMERA,                       \
    NS##_TYPE_REFLECTION,                   \
    NS##_TYPE_TRANSMISSION,                 \
    NS##_TYPE_VOLUME,                       \
    NS##_TYPE_LIGHT,                        \
    NS##_TYPE_EMISSION,                     \
    NS##_TYPE_BACKGROUND,                   \
    NS##_TYPE_EXTRA,                        \
    NS##_TYPE_MATERIAL

#define LPE_EVENT_SCATTERING_TYPE_ENUMS(NS) \
    NS##_SCATTERING_TYPE_NONE,              \
    NS##_SCATTERING_TYPE_DIFFUSE,           \
    NS##_SCATTERING_TYPE_GLOSSY,            \
    NS##_SCATTERING_TYPE_MIRROR,            \
    NS##_SCATTERING_TYPE_STRAIGHT
     
#define LPE_NO_LABEL -1

