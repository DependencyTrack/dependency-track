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
package org.dependencytrack.event;

import alpine.event.framework.AbstractChainableEvent;

import java.io.File;
import java.util.UUID;

/**
 * Defines an event triggered when VEX is submitted.
 *
 * @author Steve Springett
 * @since 4.5.0
 */
public class VexUploadEvent extends AbstractChainableEvent {

    private final UUID projectUuid;
    private File file;
    private byte[] vex;

    public VexUploadEvent(final UUID projectUuid, final byte[] vex) {
        this.projectUuid = projectUuid;
        if (vex != null) {
            this.vex = vex.clone();
        }
    }

    public VexUploadEvent(final UUID projectUuid, final File file) {
        this.projectUuid = projectUuid;
        this.file = file;
    }

    public UUID getProjectUuid() {
        return projectUuid;
    }

    public byte[] getVex() {
        return vex == null ? null : vex.clone();
    }

    public File getFile() {
        return file;
    }
}
