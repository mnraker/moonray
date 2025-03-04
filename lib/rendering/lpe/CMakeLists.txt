# Copyright 2023-2024 DreamWorks Animation LLC
# SPDX-License-Identifier: Apache-2.0

set(component rendering_lpe)

set(installIncludeDir ${PACKAGE_NAME}/rendering/lpe)
set(exportGroup ${PROJECT_NAME}Targets)

add_library(${component} SHARED "")
add_library(${PROJECT_NAME}::${component} ALIAS ${component})

# ----------------------------------------
# compile some ispc sources to object files
set(objLib ${component}_objlib)

add_library(${objLib} OBJECT)

target_sources(${objLib}
    PRIVATE
        StateMachine.ispc
)

file(RELATIVE_PATH relBinDir ${CMAKE_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR})
set_target_properties(${objLib} PROPERTIES
    ISPC_HEADER_SUFFIX _ispc_stubs.h
    ISPC_HEADER_DIRECTORY /${relBinDir}
    ISPC_INSTRUCTION_SETS ${GLOBAL_ISPC_INSTRUCTION_SETS}
    LINKER_LANGUAGE CXX
)

target_link_libraries(${objLib}
    PRIVATE SceneRdl2::common_platform)

# Set standard compile/link options
Moonray_ispc_compile_options(${objLib})
Moonray_link_options(${objLib})

get_target_property(objLibDeps ${objLib} DEPENDENCY)
if(NOT objLibDeps STREQUAL "")
    add_dependencies(${objLibDeps} 
        SceneRdl2::common_platform
    )
endif()

# ----------------------------------------

get_target_property(ISPC_TARGET_OBJECTS ${objLib} TARGET_OBJECTS)
target_sources(${component}
    PRIVATE
        osl/automata.cc
        osl/closure.cc
        osl/lpexp.cc
        osl/lpeparse.cc
        StateMachine.cc
        # pull in our ispc object files
        ${ISPC_TARGET_OBJECTS}
)

set_property(TARGET ${component}
    PROPERTY PUBLIC_HEADER
        ${CMAKE_CURRENT_BINARY_DIR}/StateMachine_ispc_stubs.h
)

target_include_directories(${component}
    INTERFACE
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(${component}
    PUBLIC
        OpenImageIO::OpenImageIO
        SceneRdl2::scene_rdl2
)

add_dependencies(${component} ${objLib})

# If at Dreamworks add a SConscript stub file so others can use this library.
SConscript_Stub(${component})

# Set standard compile/link options
Moonray_cxx_compile_definitions(${component})
Moonray_cxx_compile_features(${component})
Moonray_cxx_compile_options(${component})
Moonray_link_options(${component})

# -------------------------------------
# Install the target and the export set
# -------------------------------------
include(GNUInstallDirs)

# install the target
install(TARGETS ${component}
    COMPONENT ${component}
    EXPORT ${exportGroup}
    LIBRARY
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        NAMELINK_SKIP
    RUNTIME
        DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${installIncludeDir}
)

# # install the export set
# install(
#     EXPORT ${exportGroup}
#     NAMESPACE ${PROJECT_NAME}::
#     DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}-${PROJECT_VERSION}
# )
