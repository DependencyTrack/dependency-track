/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.parser.cyclonedx.model;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;

@XmlRootElement(name = "component", namespace = "http://cyclonedx.org/schema/bom/1.0")
public class Component {

    private String publisher;
    private String group;
    private String name;
    private String version;
    private String description;
    private String scope;
    private List<Hash> hashes = new ArrayList<>();
    private List<License> licenses = new ArrayList<>();
    private String copyright;
    private String cpe;
    private String purl;
    private boolean modified;
    private List<Component> components = new ArrayList<>();
    private String type;


    public String getPublisher() {
        return publisher;
    }

    @XmlElement(name = "publisher", namespace = "http://cyclonedx.org/schema/bom/1.0")
    public void setPublisher(String publisher) {
        this.publisher = publisher;
    }

    public String getGroup() {
        return group;
    }

    @XmlElement(name = "group", namespace = "http://cyclonedx.org/schema/bom/1.0")
    public void setGroup(String group) {
        this.group = group;
    }

    public String getName() {
        return name;
    }

    @XmlElement(name = "name", required = true, namespace = "http://cyclonedx.org/schema/bom/1.0")
    public void setName(String name) {
        this.name = name;
    }

    public String getVersion() {
        return version;
    }

    @XmlElement(name = "version", required = true, namespace = "http://cyclonedx.org/schema/bom/1.0")
    public void setVersion(String version) {
        this.version = version;
    }

    public String getDescription() {
        return description;
    }

    @XmlElement(name = "description", namespace = "http://cyclonedx.org/schema/bom/1.0")
    public void setDescription(String description) {
        this.description = description;
    }

    public String getScope() {
        return scope;
    }

    @XmlElement(name = "scope", namespace = "http://cyclonedx.org/schema/bom/1.0")
    public void setScope(String scope) {
        this.scope = scope;
    }

    public List<Hash> getHashes() {
        return hashes;
    }

    @XmlElementWrapper(name = "hashes", namespace = "http://cyclonedx.org/schema/bom/1.0")
    @XmlElement(name = "hash", namespace = "http://cyclonedx.org/schema/bom/1.0")
    public void setHashes(List<Hash> hashes) {
        this.hashes = hashes;
    }

    public List<License> getLicenses() {
        return licenses;
    }

    @XmlElementWrapper(name = "licenses", namespace = "http://cyclonedx.org/schema/bom/1.0")
    @XmlElement(name = "license", namespace = "http://cyclonedx.org/schema/bom/1.0")
    public void setLicenses(List<License> licenses) {
        this.licenses = licenses;
    }

    public String getCopyright() {
        return copyright;
    }

    @XmlElement(name = "copyright", namespace = "http://cyclonedx.org/schema/bom/1.0")
    public void setCopyright(String copyright) {
        this.copyright = copyright;
    }

    public String getCpe() {
        return cpe;
    }

    @XmlElement(name = "cpe", namespace = "http://cyclonedx.org/schema/bom/1.0")
    public void setCpe(String cpe) {
        this.cpe = cpe;
    }

    public String getPurl() {
        return purl;
    }

    @XmlElement(name = "purl", namespace = "http://cyclonedx.org/schema/bom/1.0")
    public void setPurl(String purl) {
        this.purl = purl;
    }

    public boolean isModified() {
        return modified;
    }

    @XmlElement(name = "modified", required = true, namespace = "http://cyclonedx.org/schema/bom/1.0")
    public void setModified(boolean modified) {
        this.modified = modified;
    }

    public List<Component> getComponents() {
        return components;
    }

    @XmlElementWrapper(name = "components", namespace = "http://cyclonedx.org/schema/bom/1.0")
    @XmlElement(name = "component", namespace = "http://cyclonedx.org/schema/bom/1.0")
    public void setComponents(List<Component> components) {
        this.components = components;
    }

    public String getType() {
        return type;
    }

    @XmlAttribute(name = "type", required = true)
    public void setType(String type) {
        this.type = type;
    }

}
