# Copyright 2023-2024 DreamWorks Animation LLC
# SPDX-License-Identifier: Apache-2.0

# Build up a copyright year string, eg 2017-2022
string(TIMESTAMP currentYear "%Y")
set(startingYear 2022)

if (${currentYear} GREATER ${startingYear})
    set(copyrightYear ${startingYear}-${currentYear})
else()
    set(copyrightYear ${currentYear})
endif()

set(header "// Copyright ${copyrightYear} DreamWorks Animation LLC
// SPDX-License-Identifier: Apache-2.0

// THIS FILE AUTO-GENERATED BY MoonraySamplingDefinitions.cmake

#pragma once

")

function(writeSamplingDefinitionsHeader defs)
    set(contents ${header})
    foreach(def ${defs})
        string(PREPEND def "#define ")
        string(APPEND contents ${def} "\n")
    endforeach()

    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/SamplingDefinitions.h ${contents})
    message("Generated SamplingDefinitions.h")

    # install(FILES ${CMAKE_CURRENT_BINARY_DIR}/SamplingDefinitions.h
            # DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/moonray/rendering/pbr/sampler)
endfunction()
