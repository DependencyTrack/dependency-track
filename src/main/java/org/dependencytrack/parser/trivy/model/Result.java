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
package org.dependencytrack.parser.trivy.model;

import com.google.gson.annotations.SerializedName;

public class Result {
    private String target;
    private Vulnerability[] vulnerabilities;
    private Object[] misconfigurations;
    private String resultClass;
    private String type;
    private Object[] packages;
    @SerializedName("custom_resources")
    private Object[] customResources;
    private Object[] secrets;
    private Object[] licenses;

    public String getTarget() { return target; }
    public void setTarget(String value) { this.target = value; }

    public Vulnerability[] getVulnerabilities() { return vulnerabilities; }
    public void setVulnerabilities(Vulnerability[] value) { this.vulnerabilities = value; }

    public Object[] getMisconfigurations() { return misconfigurations; }
    public void setMisconfigurations(Object[] value) { this.misconfigurations = value; }

    public String getResultClass() { return resultClass; }
    public void setResultClass(String value) { this.resultClass = value; }

    public String getType() { return type; }
    public void setType(String value) { this.type = value; }

    public Object[] getPackages() { return packages; }
    public void setPackages(Object[] value) { this.packages = value; }

    public Object[] getCustomResources() { return customResources; }
    public void setCustomResources(Object[] value) { this.customResources = value; }

    public Object[] getSecrets() { return secrets; }
    public void setSecrets(Object[] value) { this.secrets = value; }

    public Object[] getLicenses() { return licenses; }
    public void setLicenses(Object[] value) { this.licenses = value; }
}
