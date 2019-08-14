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
package org.dependencytrack.parser.dependencycheck.model;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * Defines the evidence element in a Dependency-Check report.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@XmlRootElement(name = "evidence")
public class Evidence extends BaseObject {

    private String type;
    private String confidence;
    private String source;
    private String name;
    private String value;

    public String getType() {
        return type;
    }

    @XmlAttribute(name = "type")
    public void setType(final String type) {
        this.type = normalize(type);
    }

    public String getConfidence() {
        return confidence;
    }

    @XmlAttribute(name = "confidence")
    public void setConfidence(final String confidence) {
        this.confidence = normalize(confidence);
    }

    public int getConfidenceScore() {
        return this.getConfidenceScore(this.getConfidence());
    }

    public String getSource() {
        return source;
    }

    @XmlElement(name = "source")
    public void setSource(final String source) {
        this.source = normalize(source);
    }

    public String getName() {
        return name;
    }

    @XmlElement(name = "name")
    public void setName(final String name) {
        this.name = normalize(name);
    }

    public String getValue() {
        return value;
    }

    @XmlElement(name = "value")
    public void setValue(final String value) {
        this.value = normalize(value);
    }
}
