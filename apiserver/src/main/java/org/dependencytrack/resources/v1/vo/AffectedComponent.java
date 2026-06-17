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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.resources.v1.vo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectReader;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.util.PurlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import java.util.List;
import java.util.TreeMap;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AffectedComponent {

    private static final Logger LOGGER = LoggerFactory.getLogger(AffectedComponent.class);
    private static final ObjectReader QUALIFIER_READER = Mappers.jsonMapper()
            .readerFor(new TypeReference<TreeMap<String, String>>() {
            });

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
    private List<AffectedVersionAttribution> affectedVersionAttributions;

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
                && vs.getPurlName() != null) {
            TreeMap<String, String> qualifiers = null;
            if (vs.getPurlQualifiers() != null) {
                try {
                    qualifiers = QUALIFIER_READER.readValue(vs.getPurlQualifiers());
                } catch (JsonProcessingException e) {
                    LOGGER.warn("Error deserializing PURL qualifiers: {} (skipping)", vs.getPurlQualifiers());
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
        if (vs.getVersionStartIncluding() != null
                || vs.getVersionStartExcluding() != null
                || vs.getVersionEndIncluding() != null
                || vs.getVersionEndExcluding() != null) {
            versionType = VersionType.RANGE;
            versionEndExcluding = vs.getVersionEndExcluding();
            versionEndIncluding = vs.getVersionEndIncluding();
            versionStartExcluding = vs.getVersionStartExcluding();
            versionStartIncluding = vs.getVersionStartIncluding();
        } else if (vs.getVersion() != null) {
            versionType = VersionType.EXACT;
            version = vs.getVersion();
        }
        if (vs.getAffectedVersionAttributions() != null) {
            affectedVersionAttributions = vs.getAffectedVersionAttributions();
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

    public List<AffectedVersionAttribution> getAffectedVersionAttributions() {
        return affectedVersionAttributions;
    }

    public void setAffectedVersionAttributions(List<AffectedVersionAttribution> affectedVersionAttributions) {
        this.affectedVersionAttributions = affectedVersionAttributions;
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
                LOGGER.warn("Error parsing CPE: {} (skipping)", this.identity, e);
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
                vs.setPurlQualifiers(PurlUtil.serializeQualifiers(purl));
                vs.setPurlSubpath(purl.getSubpath());
            } catch (MalformedPackageURLException e) {
                LOGGER.warn("Error parsing PURL: {} (skipping)", this.identity, e);
                return null;
            }
        }
        if (VersionType.RANGE == this.versionType) {
            vs.setVersionStartIncluding(this.versionStartIncluding);
            vs.setVersionStartExcluding(this.versionStartExcluding);
            vs.setVersionEndIncluding(this.versionEndIncluding);
            vs.setVersionEndExcluding(this.versionEndExcluding);
            vs.setAffectedVersionAttributions(this.affectedVersionAttributions);
        }
        return vs;
    }
}
