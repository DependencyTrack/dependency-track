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

/**
 * A transient object that carries component identity information.
 *
 * @since 4.0.0
 */
public class ComponentIdentity {

    private PackageURL purl;
    private String cpe;
    private String swidTagId;
    private String group;
    private String name;
    private String version;

    public ComponentIdentity(final PackageURL purl, final String cpe, final String swidTagId,
                             final String group, final String name, final String version) {
        this.purl = purl;
        this.cpe = cpe;
        this.swidTagId = swidTagId;
        this.group = group;
        this.name = name;
        this.version = version;
    }

    public ComponentIdentity(final Component component) {
        this.purl = component.getPurl();
        this.cpe = component.getCpe();
        this.swidTagId = component.getSwidTagId();
        this.group = component.getGroup();
        this.name = component.getName();
        this.version = component.getVersion();
    }

    public ComponentIdentity(final org.cyclonedx.model.Component component) {
        try {
            this.purl = new PackageURL(component.getPurl());
        } catch (MalformedPackageURLException e) {
            // throw it away
        }
        this.cpe = component.getCpe();
        this.swidTagId = (component.getSwid() != null) ? component.getSwid().getTagId() : null;
        this.group = component.getGroup();
        this.name = component.getName();
        this.version = component.getVersion();
    }

    public PackageURL getPurl() {
        return purl;
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
}
