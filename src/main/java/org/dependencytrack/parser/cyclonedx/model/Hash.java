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
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlValue;

@XmlRootElement(name = "hash", namespace = "http://cyclonedx.org/schema/bom/1.0")
public class Hash {

    private String algorithm;
    private String hash;

    public String getAlgorithm() {
        return algorithm;
    }

    @XmlAttribute(name = "alg", required = true)
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getHash() {
        return hash;
    }

    @XmlValue()
    public void setHash(String hash) {
        this.hash = hash;
    }

}
