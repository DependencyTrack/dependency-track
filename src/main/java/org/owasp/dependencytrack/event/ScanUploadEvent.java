/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
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
