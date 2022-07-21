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

import alpine.common.logging.Logger;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.model.VulnerableSoftware;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import java.util.TreeMap;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AffectedComponent {

    private static final Logger LOGGER = Logger.getLogger(AffectedComponent.class);

    enum IdentityType {
        CPE,
        PURL
    }

    enum VersionType {
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

    public AffectedComponent() {
    }

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
        } else if (vs.getPurlType() != null
                && vs.getPurlNamespace() != null
                && vs.getPurlName() != null) {
            TreeMap<String, String> qualifiers = null;
            if (vs.getPurlQualifiers() != null) {
                try {
                    qualifiers = new ObjectMapper().readValue(vs.getPurlQualifiers(), new TypeReference<>() {
                    });
                } catch (JsonProcessingException e) {
                    LOGGER.warn("Error deserializing PURL qualifiers: " + vs.getPurlQualifiers() + " (skipping)");
                }
            }

            try {
                final var purl = new PackageURL(vs.getPurlType(), vs.getPurlNamespace(), vs.getPurlName(),
                        vs.getPurlVersion(), qualifiers, vs.getPurlSubpath());
                identityType = IdentityType.PURL;
                identity = purl.canonicalize();
            } catch (MalformedPackageURLException e) {
                LOGGER.warn("Error assembling PURL", e);
            }
        }
        if (vs.getVersion() != null) {
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

    public VulnerableSoftware toVulnerableSoftware() {
        final VulnerableSoftware vs = new VulnerableSoftware();
        if (IdentityType.CPE == this.identityType && this.identity != null) {
            try {
                final Cpe cpe = CpeParser.parse(this.identity);
                vs.setCpe22(cpe.toCpe22Uri());
                vs.setCpe23(cpe.toCpe23FS());
                vs.setPart(cpe.getPart().getAbbreviation());
                vs.setVendor(cpe.getVendor());
                vs.setProduct(cpe.getProduct());
                vs.setVersion(cpe.getVersion());
                vs.setUpdate(cpe.getUpdate());
                vs.setEdition(cpe.getEdition());
                vs.setLanguage(cpe.getLanguage());
                vs.setSwEdition(cpe.getSwEdition());
                vs.setTargetSw(cpe.getTargetSw());
                vs.setTargetHw(cpe.getTargetHw());
                vs.setOther(cpe.getOther());
            } catch (CpeParsingException | CpeEncodingException e) {
                LOGGER.warn("Error parsing CPE: " + this.identity + " (skipping)", e);
                return null;
            }
        } else if (IdentityType.PURL == this.identityType && this.identity != null) {
            try {
                final PackageURL purl = new PackageURL(this.identity);
                vs.setPurl(purl.canonicalize());
                vs.setPurlType(purl.getType());
                vs.setPurlNamespace(purl.getNamespace());
                vs.setPurlName(purl.getName());
                vs.setPurlVersion(purl.getVersion());
                vs.setVersion(purl.getVersion());
                if (purl.getQualifiers() != null) {
                    vs.setPurlQualifiers(new ObjectMapper().writeValueAsString(purl.getQualifiers()));
                }
                vs.setPurlSubpath(purl.getSubpath());
            } catch (MalformedPackageURLException e) {
                LOGGER.warn("Error parsing PURL: " + this.identity + " (skipping)", e);
                return null;
            } catch (JsonProcessingException e) {
                LOGGER.warn("Error serializing PURL qualifiers: " + this.identity + " (skipping)", e);
                return null;
            }
        }
        if (VersionType.RANGE == this.versionType) {
            vs.setVersionStartIncluding(this.versionStartIncluding);
            vs.setVersionStartExcluding(this.versionStartExcluding);
            vs.setVersionEndIncluding(this.versionEndIncluding);
            vs.setVersionEndExcluding(this.versionEndExcluding);
        }
        return vs;
    }
}
