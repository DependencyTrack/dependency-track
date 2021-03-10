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

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.util.PurlUtil;
import org.json.JSONObject;
import java.util.UUID;

/**
 * A transient object that carries component identity information.
 *
 * @since 4.0.0
 */
public class ComponentIdentity {

    public enum ObjectType {
        COMPONENT,
        SERVICE
    }

    private ObjectType objectType;
    private PackageURL purl;
    private PackageURL purlCoordinates;
    private String cpe;
    private String swidTagId;
    private String group;
    private String name;
    private String version;
    private UUID uuid;

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
    }

    public ComponentIdentity(final ServiceComponent service) {
        this.group = service.getGroup();
        this.name = service.getName();
        this.version = service.getVersion();
        this.uuid = service.getUuid();
        this.objectType = ObjectType.SERVICE;
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

    public PackageURL getPurl() {
        return purl;
    }

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

    public JSONObject toJSON() {
        final JSONObject jsonObject = new JSONObject();
        jsonObject.put("uuid", this.getUuid());
        jsonObject.put("group", this.getGroup());
        jsonObject.put("name", this.getName());
        jsonObject.put("version", this.getVersion());
        jsonObject.put("purl", this.getPurl());
        jsonObject.put("purlCoordinates", this.getPurlCoordinates());
        jsonObject.put("cpe", this.getCpe());
        jsonObject.put("swidTagId", this.getSwidTagId());
        jsonObject.put("objectType", this.getObjectType());
        return jsonObject;
    }
}
