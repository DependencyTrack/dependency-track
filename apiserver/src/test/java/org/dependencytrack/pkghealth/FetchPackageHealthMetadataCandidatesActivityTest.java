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
package org.dependencytrack.pkghealth;

import com.github.packageurl.PackageURL;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.model.PackageHealthMetadataStatus;
import org.dependencytrack.persistence.jdbi.PackageHealthMetadataDao;
import org.dependencytrack.pkghealth.analyzer.PackageHealthAnalyzer;
import org.dependencytrack.pkghealth.model.AnalyzedPackageHealth;
import org.dependencytrack.pkgmetadata.PackageMetadata;
import org.dependencytrack.pkgmetadata.PackageMetadataDao;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageHealthMetadataCandidatesArg;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FetchPackageHealthMetadataCandidatesActivityTest extends PersistenceCapableTest {

    private PackageHealthAnalyzer analyzer;
    private FetchPackageHealthMetadataCandidatesActivity activity;

    @BeforeEach
    void beforeEach() {
        analyzer = mock(PackageHealthAnalyzer.class);
        when(analyzer.supportedPurlTypes()).thenReturn(Set.of("npm"));
        activity = new FetchPackageHealthMetadataCandidatesActivity(analyzer, 25);
    }

    @Test
    void shouldReturnSupportedPackagesWithoutHealthMetadata() throws Exception {
        final var supportedPurl = new PackageURL("pkg:npm/example");
        final var unsupportedPurl = new PackageURL("pkg:generic/example");

        createPackageMetadata(supportedPurl, unsupportedPurl);

        final var result = activity.execute(
                mock(ActivityContext.class),
                FetchPackageHealthMetadataCandidatesArg.newBuilder().build());

        assertThat(result.getPurlsList()).containsExactly(supportedPurl.toString());
        assertThat(result.getHasMore()).isFalse();
        assertThat(result.hasNextCursor()).isFalse();
    }

    @Test
    void shouldNotPageThroughUnsupportedPackages() throws Exception {
        activity = new FetchPackageHealthMetadataCandidatesActivity(analyzer, 1);

        // Unsupported packages never get a health row, and "pkg:generic" sorts before "pkg:npm".
        final var supportedPurl = new PackageURL("pkg:npm/example");
        createPackageMetadata(new PackageURL("pkg:generic/a"), new PackageURL("pkg:generic/b"), supportedPurl);

        final var result = activity.execute(
                mock(ActivityContext.class),
                FetchPackageHealthMetadataCandidatesArg.newBuilder().build());

        assertThat(result.getPurlsList()).containsExactly(supportedPurl.toString());
        assertThat(result.getHasMore()).isFalse();
    }

    @Test
    void shouldReturnOnlyStaleHealthMetadata() throws Exception {
        final var stalePurl = new PackageURL("pkg:npm/stale");
        final var freshPurl = new PackageURL("pkg:npm/fresh");

        createPackageMetadata(stalePurl, freshPurl);

        createHealthMetadata(stalePurl, Instant.now().minus(Duration.ofHours(25)));

        createHealthMetadata(freshPurl, Instant.now().minus(Duration.ofHours(23)));

        final var result = activity.execute(
                mock(ActivityContext.class),
                FetchPackageHealthMetadataCandidatesArg.newBuilder().build());

        assertThat(result.getPurlsList()).containsExactly(stalePurl.toString());
        assertThat(result.getHasMore()).isFalse();
    }

    private static void createHealthMetadata(final PackageURL purl, final Instant lastFetch) {
        final var source = new AnalyzedPackageHealth(purl);

        final var metadata = source.toMetadata(PackageHealthMetadataStatus.PROCESSED, lastFetch);

        useJdbiHandle(handle -> new PackageHealthMetadataDao(handle).upsertAll(List.of(metadata)));
    }

    private static void createPackageMetadata(final PackageURL... purls) {
        final var metadata = List.of(purls).stream()
                .map(purl -> new PackageMetadata(purl, "1.0.0", null, Instant.now(), "test", "test"))
                .toList();

        withJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(metadata));
    }

    @Test
    void shouldPaginateCandidatesUsingCursor() throws Exception {
        activity = new FetchPackageHealthMetadataCandidatesActivity(analyzer, 2);

        final var firstPurl = new PackageURL("pkg:npm/a");
        final var secondPurl = new PackageURL("pkg:npm/b");
        final var thirdPurl = new PackageURL("pkg:npm/c");

        createPackageMetadata(firstPurl, secondPurl, thirdPurl);

        final var firstPage = activity.execute(
                mock(ActivityContext.class),
                FetchPackageHealthMetadataCandidatesArg.newBuilder().build());

        assertThat(firstPage.getPurlsList()).containsExactly(firstPurl.toString(), secondPurl.toString());
        assertThat(firstPage.getHasMore()).isTrue();
        assertThat(firstPage.hasNextCursor()).isTrue();

        final var secondPage = activity.execute(
                mock(ActivityContext.class),
                FetchPackageHealthMetadataCandidatesArg.newBuilder()
                        .setCursor(firstPage.getNextCursor())
                        .build());

        assertThat(secondPage.getPurlsList()).containsExactly(thirdPurl.toString());
        assertThat(secondPage.getHasMore()).isFalse();
        assertThat(secondPage.hasNextCursor()).isFalse();
    }

    @Test
    void shouldRejectMalformedCursorAsTerminalFailure() {
        final var arg = FetchPackageHealthMetadataCandidatesArg.newBuilder()
                .setCursor("invalid-cursor")
                .build();

        assertThatExceptionOfType(TerminalApplicationFailureException.class)
                .isThrownBy(() -> activity.execute(mock(ActivityContext.class), arg))
                .withCauseInstanceOf(IllegalArgumentException.class);
    }
}
