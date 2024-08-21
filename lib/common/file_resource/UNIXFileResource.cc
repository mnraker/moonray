// Copyright 2023-2024 DreamWorks Animation LLC
// SPDX-License-Identifier: Apache-2.0

//

#include "UNIXFileResource.h"
#include <fstream>
#include <scene_rdl2/render/util/Strings.h>
#ifndef _MSC_VER
#include <unistd.h>
#else
#include <io.h>
#define F_OK 0
#endif

namespace moonray {
namespace file_resource {

UNIXFileResource::UNIXFileResource(const std::string& filepath)
    : mPath(filepath)
{
    mHasPound = (mPath.find('#') != std::string::npos);
}

UNIXFileResource:: ~UNIXFileResource()
{
}

std::string 
UNIXFileResource::userLabel() const
{
    return mPath;
}

std::string UNIXFileResource::fileName() const
{
    return mPath.substr(mPath.rfind('/') + 1);
}
std::string UNIXFileResource::extension() const
{
    return mPath.substr(mPath.rfind('.') + 1);
}
bool
UNIXFileResource::exists() const 
{
#ifndef _MSC_VER
    return access(mPath.c_str(), F_OK) == 0;
#else
    return _access(mPath.c_str(), F_OK) == 0;
#endif
}

std::istream*
UNIXFileResource:: openIStream()
{
    return new std::ifstream(mPath.c_str());
}

std::ostream*
UNIXFileResource:: openOStream()
{
    return new std::ofstream(mPath.c_str());
}

bool 
UNIXFileResource::supportsIndexing() const
{
    return mHasPound;
}
 
FileResource* 
UNIXFileResource::getIndexed(float indexVal) const
{
    if (!mHasPound) return NULL;

    std::string subPath(mPath);
    std::string numStr = scene_rdl2::util::buildString(indexVal);
    std::size_t numStrLength = numStr.size();

    std::size_t pos = 0;
    while (true) {
        pos = subPath.find_first_of('#', pos);
        if (pos == std::string::npos) break;
        subPath.replace(pos, 1, numStr);
        pos += numStrLength;
    }

    return new UNIXFileResource(subPath);
}

} // namespace file_resource
} // namespace moonray


