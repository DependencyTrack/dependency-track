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
package org.dependencytrack.event;

import alpine.event.framework.AbstractChainableEvent;
import org.dependencytrack.model.Project;

import static org.dependencytrack.util.PersistenceUtil.assertNonPersistent;

/**
 * Defines an event triggered when a bill-of-material (bom) document is submitted.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class BomUploadEvent extends AbstractChainableEvent {

    private final Project project;
    private final byte[] bom;

    public BomUploadEvent(final Project project, final byte[] bom) {
        assertNonPersistent(project, "project must not be persistent");
        this.project = project;
        this.bom = bom.clone();
    }

    public Project getProject() {
        return project;
    }

    public byte[] getBom() {
        return bom == null ? null : bom.clone();
    }

}
