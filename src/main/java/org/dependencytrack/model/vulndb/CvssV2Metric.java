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
package org.dependencytrack.model.vulndb;

import us.springett.cvss.CvssV2;

import java.math.BigDecimal;

/*
 * Model class needed by VulnDBAnalysis task. Class brought over from the vulndb-data-mirror repo:
 * <a href="https://github.com/stevespringett/vulndb-data-mirror">...</a>
 */
public class CvssV2Metric {
    private int id;
    private String accessComplexity;
    private String cveId;
    private String source;
    private String availabilityImpact;
    private String confidentialityImpact;
    private String authentication;
    private BigDecimal calculatedCvssBaseScore;
    private String generatedOn;
    private BigDecimal score;
    private String accessVector;
    private String integrityImpact;

    public CvssV2Metric() {
    }

    public int getId() {
        return this.id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getAccessComplexity() {
        return this.accessComplexity;
    }

    public void setAccessComplexity(String accessComplexity) {
        this.accessComplexity = accessComplexity;
    }

    public String getCveId() {
        return this.cveId;
    }

    public void setCveId(String cveId) {
        this.cveId = cveId;
    }

    public String getSource() {
        return this.source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getAvailabilityImpact() {
        return this.availabilityImpact;
    }

    public void setAvailabilityImpact(String availabilityImpact) {
        this.availabilityImpact = availabilityImpact;
    }

    public String getConfidentialityImpact() {
        return this.confidentialityImpact;
    }

    public void setConfidentialityImpact(String confidentialityImpact) {
        this.confidentialityImpact = confidentialityImpact;
    }

    public String getAuthentication() {
        return this.authentication;
    }

    public void setAuthentication(String authentication) {
        this.authentication = authentication;
    }

    public BigDecimal getCalculatedCvssBaseScore() {
        return this.calculatedCvssBaseScore;
    }

    public void setCalculatedCvssBaseScore(BigDecimal calculatedCvssBaseScore) {
        this.calculatedCvssBaseScore = calculatedCvssBaseScore;
    }

    public String getGeneratedOn() {
        return this.generatedOn;
    }

    public void setGeneratedOn(String generatedOn) {
        this.generatedOn = generatedOn;
    }

    public BigDecimal getScore() {
        return this.score;
    }

    public void setScore(BigDecimal score) {
        this.score = score;
    }

    public String getAccessVector() {
        return this.accessVector;
    }

    public void setAccessVector(String accessVector) {
        this.accessVector = accessVector;
    }

    public String getIntegrityImpact() {
        return this.integrityImpact;
    }

    public void setIntegrityImpact(String integrityImpact) {
        this.integrityImpact = integrityImpact;
    }

    public CvssV2 toNormalizedMetric() {
        CvssV2 cvss = new CvssV2();
        if (!"ADJACENT_NETWORK".equals(this.accessVector) && !"ADJACENT".equals(this.accessVector)) {
            if ("LOCAL".equals(this.accessVector)) {
                cvss.attackVector(CvssV2.AttackVector.LOCAL);
            } else if ("NETWORK".equals(this.accessVector)) {
                cvss.attackVector(CvssV2.AttackVector.NETWORK);
            }
        } else {
            cvss.attackVector(CvssV2.AttackVector.ADJACENT);
        }

        if ("SINGLE_INSTANCE".equals(this.authentication)) {
            cvss.authentication(CvssV2.Authentication.SINGLE);
        } else if ("MULTIPLE_INSTANCES".equals(this.authentication)) {
            cvss.authentication(CvssV2.Authentication.MULTIPLE);
        } else if ("NONE".equals(this.authentication)) {
            cvss.authentication(CvssV2.Authentication.NONE);
        }

        cvss.attackComplexity(CvssV2.AttackComplexity.valueOf(this.accessComplexity));
        cvss.confidentiality(CvssV2.CIA.valueOf(this.confidentialityImpact));
        cvss.integrity(CvssV2.CIA.valueOf(this.integrityImpact));
        cvss.availability(CvssV2.CIA.valueOf(this.availabilityImpact));
        return cvss;
    }
}
