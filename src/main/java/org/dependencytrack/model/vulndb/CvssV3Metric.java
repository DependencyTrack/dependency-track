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

import us.springett.cvss.CvssV3;

import java.math.BigDecimal;

/*
 * Model class needed by VulnDBAnalysis task. Class brought over from the vulndb-data-mirror repo:
 * <a href="https://github.com/stevespringett/vulndb-data-mirror">...</a>
 */
public class CvssV3Metric {
    private String attackComplexity;
    private String scope;
    private String attackVector;
    private String availabilityImpact;
    private BigDecimal score;
    private String privilegesRequired;
    private String userInteraction;
    private int id;
    private String source;
    private String cveId;
    private String confidentialityImpact;
    private BigDecimal calculatedCvssBaseScore;
    private String generatedOn;
    private String integrityImpact;

    public CvssV3Metric() {
    }

    public String getAttackComplexity() {
        return this.attackComplexity;
    }

    public void setAttackComplexity(String attackComplexity) {
        this.attackComplexity = attackComplexity;
    }

    public String getScope() {
        return this.scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getAttackVector() {
        return this.attackVector;
    }

    public void setAttackVector(String attackVector) {
        this.attackVector = attackVector;
    }

    public String getAvailabilityImpact() {
        return this.availabilityImpact;
    }

    public void setAvailabilityImpact(String availabilityImpact) {
        this.availabilityImpact = availabilityImpact;
    }

    public BigDecimal getScore() {
        return this.score;
    }

    public void setScore(BigDecimal score) {
        this.score = score;
    }

    public String getPrivilegesRequired() {
        return this.privilegesRequired;
    }

    public void setPrivilegesRequired(String privilegesRequired) {
        this.privilegesRequired = privilegesRequired;
    }

    public String getUserInteraction() {
        return this.userInteraction;
    }

    public void setUserInteraction(String userInteraction) {
        this.userInteraction = userInteraction;
    }

    public int getId() {
        return this.id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getSource() {
        return this.source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getCveId() {
        return this.cveId;
    }

    public void setCveId(String cveId) {
        this.cveId = cveId;
    }

    public String getConfidentialityImpact() {
        return this.confidentialityImpact;
    }

    public void setConfidentialityImpact(String confidentialityImpact) {
        this.confidentialityImpact = confidentialityImpact;
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

    public String getIntegrityImpact() {
        return this.integrityImpact;
    }

    public void setIntegrityImpact(String integrityImpact) {
        this.integrityImpact = integrityImpact;
    }

    public CvssV3 toNormalizedMetric() {
        CvssV3 cvss = new CvssV3();
        if (!"ADJACENT_NETWORK".equals(this.attackVector) && !"ADJACENT".equals(this.attackVector)) {
            if ("LOCAL".equals(this.attackVector)) {
                cvss.attackVector(CvssV3.AttackVector.LOCAL);
            } else if ("NETWORK".equals(this.attackVector)) {
                cvss.attackVector(CvssV3.AttackVector.NETWORK);
            } else if ("PHYSICAL".equals(this.attackVector)) {
                cvss.attackVector(CvssV3.AttackVector.PHYSICAL);
            }
        } else {
            cvss.attackVector(CvssV3.AttackVector.ADJACENT);
        }

        cvss.attackComplexity(CvssV3.AttackComplexity.valueOf(this.attackComplexity));
        cvss.privilegesRequired(CvssV3.PrivilegesRequired.valueOf(this.privilegesRequired));
        cvss.userInteraction(CvssV3.UserInteraction.valueOf(this.userInteraction));
        cvss.scope(CvssV3.Scope.valueOf(this.scope));
        cvss.confidentiality(CvssV3.CIA.valueOf(this.confidentialityImpact));
        cvss.integrity(CvssV3.CIA.valueOf(this.integrityImpact));
        cvss.availability(CvssV3.CIA.valueOf(this.availabilityImpact));
        return cvss;
    }
}
