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
package org.dependencytrack.util;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.io.IOUtils;
import java.io.ByteArrayInputStream;
import java.io.IOException;

public final class CompressUtil {

    private CompressUtil() { }

    /**
     * Helper method that attempts to automatically identify an archive and its type,
     * extract the contents as a byte array. If this fails, it will gracefully return
     * the original input byte array without exception. If the input was not an archive
     * or compressed, it will return the original byte array.
     * @param input the
     * @return a byte array
     */
    public static byte[] optionallyDecompress(final byte[] input) {
        try (final ByteArrayInputStream bis = new ByteArrayInputStream(input);
             final ArchiveInputStream ais = new ArchiveStreamFactory().createArchiveInputStream(bis)) {
            final ArchiveEntry entry = ais.getNextEntry();
            if (ais.canReadEntryData(entry)) {
                return IOUtils.toByteArray(ais);
            }
        } catch (ArchiveException | IOException e) {
            // throw it away and return the original byte array
        }
        return input;
    }

}
