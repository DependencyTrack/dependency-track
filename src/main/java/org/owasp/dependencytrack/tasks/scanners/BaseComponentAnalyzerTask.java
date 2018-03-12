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
package org.owasp.dependencytrack.tasks.scanners;

import alpine.logging.Logger;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import alpine.resources.OrderDirection;
import alpine.resources.Pagination;
import com.github.packageurl.PackageURL;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.persistence.QueryManager;

/**
 * A base class that has logic common or useful to all classes that extend it.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public abstract class BaseComponentAnalyzerTask implements ScanTask {

    /**
     * Centralized logic that governs what analyzer should perform analysis based
     * on the type of evidence provided.
     *
     * @param purl A PackageURL
     * @return true if analysis should occur, false if not
     */
    protected boolean shouldAnalyze(PackageURL purl) {
        if (this.getClass() == DependencyCheckTask.class) {
            return shouldAnalyzeWithDependencyCheck(purl);
        }
        if (this.getClass() == NspAnalysisTask.class) {
            return shouldAnalyzeWithNsp(purl);
        }
        return false;
    }

    /**
     * Determines if Dependency-Check is suitable for analysis based on the PackageURL.
     * NOTE: Although Dependency-Check is capable of analyzing many different ecosystems,
     * some analyzers are not fully compatible with the Dependency-Check ScanAgent nor
     * are they compatible with Dependency-Track.
     *
     * @param purl the PackageURL to analyze
     * @return true if Dependency-Check should analyze, false if not
     */
    protected boolean shouldAnalyzeWithDependencyCheck(PackageURL purl) {
        if (purl == null) {
            return true;
        }
        if (purl.getType().equalsIgnoreCase("npm")) {
            return false;
        }
        return true;
    }

    /**
     * Determines if the {@link NspAnalysisTask} is suitable for analysis based on the PackageURL.
     *
     * @param purl the PackageURL to analyze
     * @return true if NspAnalysisTask should analyze, false if not
     */
    protected boolean shouldAnalyzeWithNsp(PackageURL purl) {
        if (purl == null) {
            return false;
        }
        if (purl.getType().equalsIgnoreCase("npm")) {
            return true;
        }
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public void analyze() {
        Logger logger = Logger.getLogger(this.getClass()); // We don't want the base class to be the logger
        logger.info("Analyzing portfolio");
        final AlpineRequest alpineRequest = new AlpineRequest(
                null,
                new Pagination(Pagination.Strategy.OFFSET, 0, 1000),
                null,
                "id",
                OrderDirection.ASCENDING
        );
        try (QueryManager qm = new QueryManager(alpineRequest)) {
            final long total = qm.getCount(Component.class);
            long count = 0;
            while (count < total) {
                final PaginatedResult result = qm.getComponents();
                analyze(result.getList(Component.class));
                count += result.getObjects().size();
                qm.advancePagination();
            }
        }
        logger.info("Portfolio analysis complete");
    }

}
