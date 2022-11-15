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
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.dependencytrack.model.Vulnerability.Source;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

/**
 * Model class for tracking the attribution of versions affected by a given {@link Vulnerability}.
 * <p>
 * The intention behind this attribution is being able to track and differentiate which source
 * reported a given version range to be vulnerable to a given vulnerability.
 * <p>
 * Having this knowledge is especially important when multiple sources contribute intelligence data
 * for the same vulnerability. For example, both GitHub Advisories and OSV may report version ranges
 * for GHSA vulnerabilities.
 * <p>
 * Surfacing this information to users allows them to get a better understanding of why their
 * component was found to be vulnerable, and which source is responsible for it.
 *
 * @since 4.7.0
 */
@PersistenceCapable
@Index(name = "AFFECTEDVERSIONATTRIBUTION_KEYS_IDX", members = {"vulnerability", "vulnerableSoftware"})
@Unique(name = "AFFECTEDVERSIONATTRIBUTION_COMPOSITE_IDX", members = {"source", "vulnerability", "vulnerableSoftware"})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AffectedVersionAttribution implements Serializable {

    private static final long serialVersionUID = -6295453175079070126L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "FIRST_SEEN", allowsNull = "false")
    private Date firstSeen;

    @Persistent
    @Column(name = "LAST_SEEN", allowsNull = "false")
    private Date lastSeen;

    @Persistent
    @Column(name = "SOURCE", allowsNull = "false")
    private Source source;

    @Persistent
    @Column(name = "VULNERABILITY", allowsNull = "false")
    @JsonIgnore
    private Vulnerability vulnerability;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "VULNERABLE_SOFTWARE", allowsNull = "false")
    @JsonIgnore
    private VulnerableSoftware vulnerableSoftware;

    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "AFFECTEDVERSIONATTRIBUTION_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    private UUID uuid;

    public AffectedVersionAttribution() {
    }

    public AffectedVersionAttribution(final Source source, final Vulnerability vulnerability, final VulnerableSoftware vulnerableSoftware) {
        this.source = Objects.requireNonNull(source, "source must not be null");
        this.vulnerability = Objects.requireNonNull(vulnerability, "vulnerability must not be null");
        this.vulnerableSoftware = Objects.requireNonNull(vulnerableSoftware, "vulnerableSoftware must not be null");
        this.firstSeen = new Date();
        this.lastSeen = this.firstSeen;
    }

    public long getId() {
        return id;
    }

    public void setId(final long id) {
        this.id = id;
    }

    public Date getFirstSeen() {
        return firstSeen;
    }

    public void setFirstSeen(final Date firstSeen) {
        this.firstSeen = firstSeen;
    }

    public Date getLastSeen() {
        return lastSeen;
    }

    public void setLastSeen(final Date lastSeen) {
        this.lastSeen = lastSeen;
    }

    public Source getSource() {
        return source;
    }

    public void setSource(final Source source) {
        this.source = source;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(final Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }

    public VulnerableSoftware getVulnerableSoftware() {
        return vulnerableSoftware;
    }

    public void setVulnerableSoftware(final VulnerableSoftware vulnerableSoftware) {
        this.vulnerableSoftware = vulnerableSoftware;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(final UUID uuid) {
        this.uuid = uuid;
    }

}
