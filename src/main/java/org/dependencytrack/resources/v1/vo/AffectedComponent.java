/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.resources.v1.vo;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.dependencytrack.model.VulnerableSoftware;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AffectedComponent {

    private enum IdentityType {
        CPE,
        PURL
    }

    private enum VersionType {
        EXACT,
        RANGE
    }

    private IdentityType identityType;
    private String identity;
    private VersionType versionType;
    private String version;
    private String versionEndExcluding;
    private String versionEndIncluding;
    private String versionStartExcluding;
    private String versionStartIncluding;
    private UUID uuid;

    public AffectedComponent() {}

    public AffectedComponent(final VulnerableSoftware vs) {
        if (vs.getCpe23() != null) {
            identityType = IdentityType.CPE;
            identity = vs.getCpe23();
        } else if (vs.getCpe22() != null) {
            identityType = IdentityType.CPE;
            identity = vs.getCpe22();
        } else if (vs.getPurl() != null) {
            identityType = IdentityType.PURL;
            identity = vs.getPurl();
        }
        if (version != null) {
            versionType = VersionType.EXACT;
            version = vs.getVersion();
        } else {
            versionType = VersionType.RANGE;
            versionEndExcluding = vs.getVersionEndExcluding();
            versionEndIncluding = vs.getVersionEndIncluding();
            versionStartExcluding = vs.getVersionStartExcluding();
            versionStartIncluding = vs.getVersionStartIncluding();
        }
        uuid = vs.getUuid();
    }

    public IdentityType getIdentityType() {
        return identityType;
    }

    public void setIdentityType(IdentityType identityType) {
        this.identityType = identityType;
    }

    public String getIdentity() {
        return identity;
    }

    public void setIdentity(String identity) {
        this.identity = identity;
    }

    public VersionType getVersionType() {
        return versionType;
    }

    public void setVersionType(VersionType versionType) {
        this.versionType = versionType;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getVersionEndExcluding() {
        return versionEndExcluding;
    }

    public void setVersionEndExcluding(String versionEndExcluding) {
        this.versionEndExcluding = versionEndExcluding;
    }

    public String getVersionEndIncluding() {
        return versionEndIncluding;
    }

    public void setVersionEndIncluding(String versionEndIncluding) {
        this.versionEndIncluding = versionEndIncluding;
    }

    public String getVersionStartExcluding() {
        return versionStartExcluding;
    }

    public void setVersionStartExcluding(String versionStartExcluding) {
        this.versionStartExcluding = versionStartExcluding;
    }

    public String getVersionStartIncluding() {
        return versionStartIncluding;
    }

    public void setVersionStartIncluding(String versionStartIncluding) {
        this.versionStartIncluding = versionStartIncluding;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }
}
