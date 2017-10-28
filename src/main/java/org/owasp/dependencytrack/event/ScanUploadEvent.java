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
package org.owasp.dependencytrack.event;

import alpine.event.framework.Event;
import java.io.File;
import java.util.UUID;

/**
 * Defines an event triggered when a Dependency-Check scan is submitted.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class ScanUploadEvent implements Event {

    private UUID projectUuid;
    private File file;
    private byte[] scan;

    public ScanUploadEvent(final UUID projectUuid, final byte[] scan) {
        this.projectUuid = projectUuid;
        this.scan = scan;
    }

    public ScanUploadEvent(final UUID projectUuid, final File file) {
        this.projectUuid = projectUuid;
        this.file = file;
    }

    public UUID getProjectUuid() {
        return projectUuid;
    }

    public byte[] getScan() {
        return scan;
    }

    public File getFile() {
        return file;
    }
}
