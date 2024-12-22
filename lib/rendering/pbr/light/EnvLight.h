// Copyright 2023-2024 DreamWorks Animation LLC
// SPDX-License-Identifier: Apache-2.0


#pragma once

#include "Light.h"

#include <scene_rdl2/common/math/Color.h>
#include <scene_rdl2/common/math/Mat4.h>
#include <scene_rdl2/common/math/ReferenceFrame.h>
#include <scene_rdl2/common/math/Vec3.h>

// Forward declaration of the ISPC types
namespace ispc {
    struct EnvLight;
}


namespace scene_rdl2 {
namespace rdl2 {
    class Light;
}
}

namespace moonray {
namespace pbr {

class PathVertex;

//----------------------------------------------------------------------------

/// @brief Implements light sampling for environment lights.
/// @brief Implements light sampling for textured infinite spherical environment
/// lights. Only the rotation of the w2c transform will have an effect.

class EnvLight : public Light
{
    friend class EnvLightTester;

public:
    /// Constructor / Destructor
    explicit EnvLight(const scene_rdl2::rdl2::Light* rdlLight);
    virtual ~EnvLight();

    /// HUD validation and type casting
    static uint32_t hudValidation(bool verbose) {
        ENV_LIGHT_VALIDATION;
    }
    HUD_AS_ISPC_METHODS(EnvLight);


    virtual bool update(const scene_rdl2::math::Mat4d& world2render) override;

    /// Intersection and sampling API
    virtual bool canIlluminate(const scene_rdl2::math::Vec3f p, const scene_rdl2::math::Vec3f *n, float time, float radius,
            const LightFilterList* lightFilterList, const PathVertex* pv) const override
    {
        MNRY_ASSERT(mOn);
        // Only illuminate if we are not using a PortalLight
        return !mHasPortal;
    }
    virtual bool isBounded() const override;
    virtual bool isDistant() const override;
    virtual bool isEnv() const override;
    virtual bool intersect(const scene_rdl2::math::Vec3f &p, const scene_rdl2::math::Vec3f *n, 
            const scene_rdl2::math::Vec3f &wi, float time, float maxDistance, LightIntersection &isect) const override;
    virtual bool sample(const scene_rdl2::math::Vec3f &p, const scene_rdl2::math::Vec3f *n, float time, 
            const scene_rdl2::math::Vec3f& r, scene_rdl2::math::Vec3f &wi, LightIntersection &isect, 
            float rayDirFootprint) const override;
    virtual scene_rdl2::math::Color eval(mcrt_common::ThreadLocalState* tls, const scene_rdl2::math::Vec3f &wi, 
            const scene_rdl2::math::Vec3f &p, const LightFilterRandomValues& filterR, float time, 
            const LightIntersection &isect, bool fromCamera, const LightFilterList *lightFilterList, 
            const PathVertex *pv, float rayDirFootprint, float *visibility, float *pdf) const override;

    virtual scene_rdl2::math::Vec3f getEquiAngularPivot(const scene_rdl2::math::Vec3f& r, float time) const override;

    // A value of -1 for both indicates that this type of light (unbounded)
    // should always be sampled (i.e. not included in the light sampling BVH)
    float getThetaO() const override { return -1.f; }
    float getThetaE() const override { return -1.f; }

private:
    void initAttributeKeys(const scene_rdl2::rdl2::SceneClass &sc);

    scene_rdl2::math::Vec3f localToGlobal(const scene_rdl2::math::Vec3f &v, float time) const;
    scene_rdl2::math::Vec3f globalToLocal(const scene_rdl2::math::Vec3f &v, float time) const;
    scene_rdl2::math::Xform3f globalToLocalXform(float time, bool needed = true) const;

    /// Copy is disabled
    EnvLight(const EnvLight &other);
    const EnvLight &operator=(const EnvLight &other);

    // rayDirFootprint is already a logarithmic value so the mip level is just the difference.
    // TODO: it may be a good idea to include an rdla-controllable mip bias in this calculation.
    float getMipLevel(float rayDirFootprint) const
    {
        return rayDirFootprint - mLog2TexelAngle;
    }


    ENV_LIGHT_MEMBERS;

    //
    // Cached attribute keys:
    //
    // cppcheck-suppress duplInheritedMember
    static bool sAttributeKeyInitialized;
    static scene_rdl2::rdl2::AttributeKey<scene_rdl2::rdl2::Bool> sSampleUpperHemisphereOnlyKey;

    static const scene_rdl2::math::Mat4f sLocalOrientation;
};

//----------------------------------------------------------------------------

} // namespace pbr
} // namespace moonray

