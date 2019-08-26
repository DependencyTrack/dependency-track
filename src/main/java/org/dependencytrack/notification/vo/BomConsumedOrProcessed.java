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
package org.dependencytrack.notification.vo;

import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Project;

public class BomConsumedOrProcessed {

    private Project project;
    private String bom;
    private Bom.Format format;
    private String specVersion;

    public BomConsumedOrProcessed(final Project project, final String bom, final Bom.Format format, final String specVersion) {
        this.project = project;
        this.bom = bom;
        this.format = format;
        this.specVersion = specVersion;
    }

    public Project getProject() {
        return project;
    }

    public String getBom() {
        return bom;
    }

    public Bom.Format getFormat() {
        return format;
    }

    public String getSpecVersion() {
        return specVersion;
    }
}
