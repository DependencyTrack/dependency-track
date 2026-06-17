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
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.resources.v1.serializers.CustomPackageURLSerializer;
import org.dependencytrack.util.PurlUtil;

import java.util.Objects;
import java.util.UUID;

/**
 * A transient object that carries component identity information.
 *
 * @since 4.0.0
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ComponentIdentity {

    public enum ObjectType {
        COMPONENT,
        SERVICE
    }
    private Scope scope;

    private final ObjectType objectType;
    private PackageURL purl;
    private PackageURL purlCoordinates;
    private String cpe;
    private String swidTagId;
    private final String group;
    private final String name;
    private final String version;
    private UUID uuid;
    private Scope scope;

    public ComponentIdentity(final PackageURL purl, final String cpe, final String swidTagId,
                             final String group, final String name, final String version) {
        this.purl = purl;
        this.purlCoordinates = PurlUtil.silentPurlCoordinatesOnly(purl);
        this.cpe = cpe;
        this.swidTagId = swidTagId;
        this.group = group;
        this.name = name;
        this.version = version;
        this.objectType = ObjectType.COMPONENT;
    }

    public ComponentIdentity(final Component component) {
        this.purl = component.getPurl();
        this.purlCoordinates = PurlUtil.silentPurlCoordinatesOnly(purl);
        this.cpe = component.getCpe();
        this.swidTagId = component.getSwidTagId();
        this.group = component.getGroup();
        this.name = component.getName();
        this.version = component.getVersion();
        this.uuid = component.getUuid();
        this.objectType = ObjectType.COMPONENT;
        this.scope = component.getScope();
    }

    public ComponentIdentity(final Component component, final boolean excludeUuid) {
        this(component);
        if (excludeUuid) {
            this.uuid = null;
        }
    }

    public ComponentIdentity(final org.cyclonedx.model.Component component) {
        try {
            this.purl = new PackageURL(component.getPurl());
            this.purlCoordinates = PurlUtil.purlCoordinatesOnly(purl);
        } catch (MalformedPackageURLException e) {
            // throw it away
        }
        this.cpe = component.getCpe();
        this.swidTagId = (component.getSwid() != null) ? component.getSwid().getTagId() : null;
        this.group = component.getGroup();
        this.name = component.getName();
        this.version = component.getVersion();
        this.objectType = ObjectType.COMPONENT;
        this.scope = Scope.getMappedScope(component.getScope());
    }

    public ComponentIdentity(final ServiceComponent service) {
        this.group = service.getGroup();
        this.name = service.getName();
        this.version = service.getVersion();
        this.uuid = service.getUuid();
        this.objectType = ObjectType.SERVICE;
    }

    public ComponentIdentity(final ServiceComponent service, final boolean excludeUuid) {
        this(service);
        if (excludeUuid) {
            this.uuid = null;
        }
    }

    public ComponentIdentity(final org.cyclonedx.model.Service service) {
        this.group = service.getGroup();
        this.name = service.getName();
        this.version = service.getVersion();
        this.objectType = ObjectType.SERVICE;
    }

    public ObjectType getObjectType() {
        return objectType;
    }

    @JsonSerialize(using = CustomPackageURLSerializer.class)
    public PackageURL getPurl() {
        return purl;
    }

    @JsonSerialize(using = CustomPackageURLSerializer.class)
    public PackageURL getPurlCoordinates() {
        return purlCoordinates;
    }

    public String getCpe() {
        return cpe;
    }

    public String getSwidTagId() {
        return swidTagId;
    }

    public String getGroup() {
        return group;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    public UUID getUuid() {
        return uuid;
    }

    public Scope getScope() {
        return scope;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        final ComponentIdentity that = (ComponentIdentity) o;
        return objectType == that.objectType && Objects.equals(purl, that.purl) && Objects.equals(purlCoordinates, that.purlCoordinates) && Objects.equals(cpe, that.cpe) && Objects.equals(swidTagId, that.swidTagId) && Objects.equals(group, that.group) && Objects.equals(name, that.name) && Objects.equals(version, that.version) && Objects.equals(uuid, that.uuid) && Objects.equals(scope, that.scope);
    }

    @Override
    public int hashCode() {
        return Objects.hash(objectType, purl, purlCoordinates, cpe, swidTagId, group, name, version, uuid, scope);
    }

    public ObjectNode toJSON() {
        return Mappers.jsonMapper().valueToTree(this);
    }

}
