/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.parser.dependencycheck.model;

import org.owasp.dependencycheck.dependency.Confidence;
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
    public void setType(String type) {
        this.type = normalize(type);
    }

    public String getConfidence() {
        return confidence;
    }

    public Confidence getConfidenceType() {
        return getConfidenceFromString(confidence);
    }

    @XmlAttribute(name = "confidence")
    public void setConfidence(String confidence) {
        this.confidence = normalize(confidence);
    }

    public int getConfidenceScore() {
        return this.getConfidenceScore(this.getConfidenceType());
    }

    public String getSource() {
        return source;
    }

    @XmlElement(name = "source")
    public void setSource(String source) {
        this.source = normalize(source);
    }

    public String getName() {
        return name;
    }

    @XmlElement(name = "name")
    public void setName(String name) {
        this.name = normalize(name);
    }

    public String getValue() {
        return value;
    }

    @XmlElement(name = "value")
    public void setValue(String value) {
        this.value = normalize(value);
    }
}
