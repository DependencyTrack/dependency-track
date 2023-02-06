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
package org.dependencytrack.parser.osv.model;

import org.dependencytrack.model.Severity;

public class OsvAffectedPackage {
    private String packageName;

    private String packageEcosystem;

    private String purl;

    private String lowerVersionRange;

    private String upperVersionRangeExcluding;

    private String upperVersionRangeIncluding;

    private Severity severity;

    private Double cvssScore;

    private String version;

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getPackageEcosystem() {
        return packageEcosystem;
    }

    public void setPackageEcosystem(String packageEcosystem) {
        this.packageEcosystem = packageEcosystem;
    }

    public String getPurl() {
        return purl;
    }

    public void setPurl(String purl) {
        this.purl = purl;
    }

    public String getLowerVersionRange() {
        return lowerVersionRange;
    }
    public void setLowerVersionRange(String lowerVersionRange) {
        this.lowerVersionRange = lowerVersionRange;
    }
    public String getUpperVersionRangeExcluding() {
        return upperVersionRangeExcluding;
    }
    public void setUpperVersionRangeExcluding(String upperVersionRange) {
        this.upperVersionRangeExcluding = upperVersionRange;
    }

    public Severity getSeverity() {
        return severity;
    }
    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public Double getCvssScore() {
        return cvssScore;
    }

    public void setCvssScore(double cvssScore) {
        this.cvssScore = cvssScore;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getUpperVersionRangeIncluding() {
        return upperVersionRangeIncluding;
    }

    public void setUpperVersionRangeIncluding(String upperVersionRangeIncluding) {
        this.upperVersionRangeIncluding = upperVersionRangeIncluding;
    }
}