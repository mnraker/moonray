# Copyright 2023-2025 DreamWorks Animation LLC
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required (VERSION 3.23.1)

include(OMR_PackageVersion)  # Sets versionString, projectString and PACKAGE_NAME
set(languages LANGUAGES CXX C)
if(NOT CMAKE_XCODE_BUILD_SYSTEM)
    list(APPEND languages ISPC)
endif()
project(${projectString}
    VERSION ${versionString}
    ${languages})

string(TOUPPER ${PROJECT_NAME} PROJECT_NAME_UPPER)
list(APPEND CMAKE_MESSAGE_CONTEXT ${PROJECT_NAME})
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include(MoonrayCheckFeature)

include(OMR_Platform)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
endif()

# ================================================
# Options
# ================================================
option(${PROJECT_NAME_UPPER}_BUILD_AMORPHOUS_VOLUME
    "Build the AmorphousVolume class" NO)
option(${PROJECT_NAME_UPPER}_BUILD_BRDF_CMDS
    "Build the sample point generation cmds" NO)
option(${PROJECT_NAME_UPPER}_BUILD_POINT_GENERATION_CMDS
    "Build the sample point generation cmds" NO)
option(${PROJECT_NAME_UPPER}_BUILD_TESTING
    "Whether or not to build the unittests" YES)
option(${PROJECT_NAME_UPPER}_DWA_BUILD
    "Whether to enable DWA-specific features" NO)

# Ideally MOONRAY_DWA_BUILD should be set to YES externally (e.g. by rez-build), but this
# is a fallback to enable it if STUDIO=GLD...
if(GLD STREQUAL "$ENV{STUDIO}")
    set(${PROJECT_NAME_UPPER}_DWA_BUILD YES)
endif()

option(ABI_SET_VERSION "Enable the abi-version option" OFF)
if(ABI_SET_VERSION)
    set(ABI_VERSION "6" CACHE STRING "If ABI_SET_VERSION is on, which version to set")
endif()

# ================================================
# Find dependencies
# ================================================

find_package(BISON) # built-in
find_package(FLEX)  # built-in

set(BUILD_SHARED_LIBS ON)
find_package(Boost REQUIRED)

if(MOONRAY_USE_OPTIX)
    include(CheckLanguage)
    check_language(CUDA)
    if(CMAKE_CUDA_COMPILER)
        enable_language(CUDA)
    else()
        message(STATUS "No CUDA support")
    endif()
    find_package(CUDAToolkit REQUIRED) # built-in
    find_package(OptiX REQUIRED)
endif()

if (MOONRAY_USE_METAL)
    if(IsDarwinPlatform)
        check_language(OBJCXX)
        if(CMAKE_OBJCXX_COMPILER)
            enable_language(OBJCXX)
        else()
            message(STATUS "No OBJCC support")
        endif()
    endif()
    find_library(Metal Metal)
    add_library(Metal::Metal INTERFACE IMPORTED)
    set_target_properties(Metal::Metal PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES "CXX")
endif()

find_package(Amorphous QUIET)
if(${Amorphous_FOUND})
    set(AMORPHOUS Amorphous::Amorphous)
    set(${PROJECT_NAME_UPPER}_BUILD_AMORPHOUS_VOLUME YES)
endif()

if(NOT IsDarwinPlatform)
    find_package(Libatomic REQUIRED)
endif()

find_package(ZLIB REQUIRED)
find_package(IlmBase QUIET)
find_package(Imath QUIET)
find_package(JPEG REQUIRED)
if("${PROJECT_NAME}" STREQUAL "${CMAKE_PROJECT_NAME}")
    find_package(SceneRdl2 REQUIRED)
    find_package(McrtDenoise REQUIRED)
endif()
find_package(OpenEXR REQUIRED)
if(TARGET OpenEXR::IlmImfUtil)
    set(OPENEXRUTIL OpenEXR::IlmImfUtil)
    set(OPENEXRIEX IlmBase::Iex)
    set(OPENEXRILMTHREAD IlmBase::IlmThread)
    set(OPENEXROPENEXR OpenEXR::IlmImf)
    set(IMATHIMATH IlmBase::Imath IlmBase::Half)
else()
    set(OPENEXRUTIL OpenEXR::OpenEXRUtil)
    set(OPENEXRIEX OpenEXR::Iex)
    set(OPENEXRILMTHREAD OpenEXR::IlmThread)
    set(OPENEXROPENEXR OpenEXR::OpenEXR)
    set(IMATHIMATH Imath::Imath)
endif()
find_package(OpenVDB REQUIRED)
find_package(OpenSubDiv REQUIRED)
find_package(Embree 4.2 REQUIRED)
find_package(OpenImageIO REQUIRED)
find_package(Random123 REQUIRED)
find_package(OpenImageIO REQUIRED)
find_package(TBB REQUIRED)
# Intel Math Kernel is not required by Moonray itself, but currently it has to
# be linked into the application if any dsos require it. Therefore we link it
# if it is available
find_package(Mkl QUIET)
if(${Mkl_FOUND})
    set(MKL Mkl::Mkl)
endif()

# Set the RPATH for binaries in the install tree
set(CMAKE_INSTALL_RPATH ${GLOBAL_INSTALL_RPATH})
if(NOT IsDarwinPlatform)
    set(CMAKE_BUILD_RPATH ${COMPILER_LIBRARY_DIR})
endif()
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)


# ===============================================
# Set the install directory for rdl2 dsos
# ===============================================
set(RDL2DSO_INSTALL_DIR rdl2dso)
set(RDL2DSO_PROXY_INSTALL_DIR rdl2dso.proxy)

# if OPT_LEVEL is set use its value to override the CMAKE_BUILD_TYPE because the
# rez cmake plugin does not have an easy way to set the build_target.
set(opt_level $ENV{OPT_LEVEL})
if(opt_level STREQUAL opt-debug)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
elseif(opt_level STREQUAL debug)
    set(CMAKE_BUILD_TYPE Debug)
elseif(opt_level STREQUAL opt)
    set(CMAKE_BUILD_TYPE Release)
endif()

# default to Release if no build type specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Create include/${PACKAGE_NAME} link in the build directory for generated headers.
file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/include)
file(CREATE_LINK ../lib ${PROJECT_BINARY_DIR}/include/${PACKAGE_NAME} SYMBOLIC)

include(${PROJECT_NAME}CompileDefinitions)
include(${PROJECT_NAME}CompileFeatures)
include(${PROJECT_NAME}CompileOptions)
include(${PROJECT_NAME}LinkOptions)
include(SConscriptStub)

# ================================================
# Add project files
# ================================================
add_subdirectory(lib)
add_subdirectory(cmd)
add_subdirectory(dso)
if(GLD STREQUAL "$ENV{STUDIO}")
    if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
        add_subdirectory(bart_tools)
        install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/SDKScript
            DESTINATION .
            PERMISSIONS
              OWNER_READ OWNER_WRITE
              GROUP_READ GROUP_WRITE
              WORLD_READ
        )
    endif()
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/SConscripts
        DESTINATION .
        FILE_PERMISSIONS
          OWNER_READ OWNER_WRITE
          GROUP_READ GROUP_WRITE
          WORLD_READ
        DIRECTORY_PERMISSIONS
          OWNER_READ OWNER_EXECUTE OWNER_WRITE
          GROUP_READ GROUP_EXECUTE GROUP_WRITE
          WORLD_READ WORLD_EXECUTE)
endif()

if((CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME OR ${PROJECT_NAME_UPPER}_BUILD_TESTING)
        AND BUILD_TESTING)
    find_package(CppUnit REQUIRED)
    add_subdirectory(tests)
endif()

# ================================================
# Install
# ================================================
include(GNUInstallDirs)
install(EXPORT ${PROJECT_NAME}Targets
        FILE ${PROJECT_NAME}Targets.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}-${PROJECT_VERSION}
        NAMESPACE ${PROJECT_NAME}::)

include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${PROJECT_SOURCE_DIR}/cmake/${PROJECT_NAME}Config.cmake.in
    ${PROJECT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    INSTALL_DESTINATION
        ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}-${PROJECT_VERSION}
)

write_basic_package_version_file(
    ${PROJECT_NAME}ConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMinorVersion
)

install(
    FILES
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
    DESTINATION
        ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}-${PROJECT_VERSION}
)

