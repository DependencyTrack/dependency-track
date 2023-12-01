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
package org.dependencytrack.parser.trivy.model;

public class Cvss {
    private Bitnami ghsa;
    private Bitnami nvd;
    private Bitnami redhat;
    private Bitnami bitnami;

    public Bitnami getGhsa() { return ghsa; }
    public void setGhsa(Bitnami value) { this.ghsa = value; }

    public Bitnami getNvd() { return nvd; }
    public void setNvd(Bitnami value) { this.nvd = value; }

    public Bitnami getRedhat() { return redhat; }
    public void setRedhat(Bitnami value) { this.redhat = value; }

    public Bitnami getBitnami() { return bitnami; }
    public void setBitnami(Bitnami value) { this.bitnami = value; }
}