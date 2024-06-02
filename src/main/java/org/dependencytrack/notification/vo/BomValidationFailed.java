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
package org.dependencytrack.notification.vo;

import java.util.List;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Project;

public class BomValidationFailed {

    private Project project;
    private String bom;
    private List<String> errors;
    private Bom.Format format;

    public BomValidationFailed(final Project project, final String bom, final List<String> errors, final Bom.Format format) {
        this.project = project;
        this.bom = bom;
        this.errors = errors;
        this.format = format;
    }

    public Project getProject() {
        return project;
    }

    public String getBom() {
        return bom;
    }

    public List<String> getErrors() {
        return errors;
    }

    public Bom.Format getFormat() {
        return format;
    }

}
