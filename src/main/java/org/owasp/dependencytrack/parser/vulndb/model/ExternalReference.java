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
package org.owasp.dependencytrack.parser.vulndb.model;

/**
 * The response from VulnDB Vulnerability API will respond with 0 or more external
 * references. This class defines the ExternalReference objects returned.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class ExternalReference {

    /**
     * Type of the external source ex: CVE ID.
     */
    private String type;

    /**
     * The related value in the external source ex: 1999-0449.
     */
    private String value;


    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
