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
package org.dependencytrack.search;

import org.apache.lucene.util.InfoStream;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * Lucene {@link InfoStream} implementation for Dependency-Track's SLF4J-based logging mechanism.
 * <p>
 * Logging of Lucene messages can be enabled on a per-index basis:
 *
 * <pre>{@code
 *     <logger name="org.dependencytrack.search.VulnerabilityIndexer.lucene" level="DEBUG" additivity="false">
 *         <appender-ref ref="STDOUT"/>
 *     </logger>
 * }</pre>
 * <p>
 * It is also possible to enable logging selectively for specific Lucene components:
 *
 * <pre>{@code
 *     <logger name="org.dependencytrack.search.VulnerabilityIndexer.lucene.IW" level="DEBUG" additivity="false">
 *         <appender-ref ref="STDOUT"/>
 *     </logger>
 * }</pre>
 * <p>
 * A few known Lucene components and their abbreviations are:
 * <ul>
 *     <li>{@link org.apache.lucene.index.DocumentsWriterFlushControl} (DWFC)</li>
 *     <li>{@link org.apache.lucene.index.DocumentsWriter} (DW)</li>
 *     <li>{@link org.apache.lucene.index.IndexFileDeleter} (IFD)</li>
 *     <li>{@link org.apache.lucene.index.IndexWriter} (IW)</li>
 *     <li>{@link org.apache.lucene.index.MergePolicy} (MP)</li>
 *     <li>{@link org.apache.lucene.index.MergeScheduler} (MS)</li>
 * </ul>
 *
 * @since 4.11.0
 */
@SuppressWarnings("JavadocReference")
class LoggingInfoStream extends InfoStream {

    private final Class<?> parentLoggerClass;

    LoggingInfoStream(final Class<?> parentLoggerClass) {
        this.parentLoggerClass = parentLoggerClass;
    }

    @Override
    public void message(final String component, final String message) {
        getLogger(component).debug(message);
    }

    @Override
    public boolean isEnabled(final String component) {
        return getLogger(component).isDebugEnabled();
    }

    @Override
    public void close() throws IOException {
    }

    private org.slf4j.Logger getLogger(final String component) {
        final String loggerName = "%s.lucene.%s".formatted(parentLoggerClass.getName(), component);
        return LoggerFactory.getLogger(loggerName);
    }

}
