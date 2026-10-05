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

import com.google.protobuf.util.Timestamps;
import org.dependencytrack.model.PackageHealthMetadata;
import org.dependencytrack.model.PackageHealthScorecardCheck;
import org.dependencytrack.proto.policy.v1.HealthMeta;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;

/**
 * Compares the package health values that component policies can read.
 * <p>
 * The values are compared in their policy form, {@link HealthMeta}, so that a field added to the
 * policy type is compared without further changes here.
 * <p>
 * Average issue age and commit frequency are computed relative to the time of the fetch,
 * so they change on every refresh even when nothing changed upstream. Those changes are
 * not reported, so that an unchanged refresh does not start policy evaluation.
 */
final class PackageHealthPolicyDelta {

    /**
     * Smallest change in average issue age, beyond the time elapsed between fetches,
     * that counts as a change.
     */
    private static final double ISSUE_AGE_TOLERANCE_DAYS = 1.0;

    /**
     * Smallest relative change in commit frequency that counts as a change. Commit frequency
     * divides by the repository age in weeks, so it shrinks by less than 2% per week for
     * repositories older than a year without any new commits.
     */
    private static final double COMMIT_FREQUENCY_RELATIVE_TOLERANCE = 0.05;

    private PackageHealthPolicyDelta() {}

    static boolean changed(final @Nullable PackageHealthMetadata previous, final PackageHealthMetadata next) {
        final HealthMeta nextValues = policyValues(next);
        if (previous == null) {
            return !nextValues.equals(HealthMeta.getDefaultInstance());
        }

        final HealthMeta previousValues = policyValues(previous);
        return !withoutTimeDrivenValues(previousValues).equals(withoutTimeDrivenValues(nextValues))
                || commitFrequencyChanged(previousValues, nextValues)
                || issueAgeChanged(previous, previousValues, next, nextValues);
    }

    /**
     * Converts the stored health to the values a component policy sees. Checks are sorted by name,
     * so that their order does not count as a change.
     */
    static HealthMeta policyValues(final PackageHealthMetadata metadata) {
        final HealthMeta.Builder builder = HealthMeta.newBuilder();
        if (metadata.scorecardScore() != null) {
            builder.setScorecardScore(metadata.scorecardScore());
        }
        if (metadata.averageIssueAgeDays() != null) {
            builder.setAvgIssueAgeDays(metadata.averageIssueAgeDays());
        }
        if (metadata.commitFrequencyWeekly() != null) {
            builder.setCommitFrequencyWeekly(metadata.commitFrequencyWeekly());
        }
        if (metadata.lastCommit() != null) {
            builder.setLastCommit(Timestamps.fromMillis(metadata.lastCommit().toEpochMilli()));
        }
        if (metadata.dependents() != null) {
            builder.setDependents(metadata.dependents());
        }
        if (metadata.busFactor() != null) {
            builder.setBusFactor(metadata.busFactor());
        }
        if (metadata.stars() != null) {
            builder.setStars(metadata.stars());
        }
        if (metadata.forks() != null) {
            builder.setForks(metadata.forks());
        }
        if (metadata.repositoryArchived() != null) {
            builder.setIsRepoArchived(metadata.repositoryArchived());
        }
        metadata.scorecardChecks().stream()
                .sorted(Comparator.comparing(PackageHealthScorecardCheck::name))
                .forEach(check -> {
                    final var protoCheck =
                            HealthMeta.ScorecardCheck.newBuilder().setName(check.name());
                    if (check.score() != null) {
                        protoCheck.setScore(check.score());
                    }
                    builder.addScorecardChecks(protoCheck);
                });
        return builder.build();
    }

    private static HealthMeta withoutTimeDrivenValues(final HealthMeta values) {
        return values.toBuilder()
                .clearAvgIssueAgeDays()
                .clearCommitFrequencyWeekly()
                .build();
    }

    private static boolean issueAgeChanged(
            final PackageHealthMetadata previous,
            final HealthMeta previousValues,
            final PackageHealthMetadata next,
            final HealthMeta nextValues) {
        if (previousValues.hasAvgIssueAgeDays() != nextValues.hasAvgIssueAgeDays()) {
            return true;
        }
        if (!nextValues.hasAvgIssueAgeDays()) {
            return false;
        }

        final float previousAge = previousValues.getAvgIssueAgeDays();
        final float nextAge = nextValues.getAvgIssueAgeDays();
        if (previousAge == nextAge) {
            return false;
        }

        final Instant previousFetch = previous.lastFetch();
        final Instant nextFetch = next.lastFetch();
        final double elapsedDays = previousFetch != null && nextFetch != null
                ? Duration.between(previousFetch, nextFetch).toSeconds() / 86_400.0
                : 0;
        return Math.abs(nextAge - (previousAge + elapsedDays)) >= ISSUE_AGE_TOLERANCE_DAYS;
    }

    private static boolean commitFrequencyChanged(final HealthMeta previousValues, final HealthMeta nextValues) {
        if (previousValues.hasCommitFrequencyWeekly() != nextValues.hasCommitFrequencyWeekly()) {
            return true;
        }
        if (!nextValues.hasCommitFrequencyWeekly()) {
            return false;
        }

        final float previous = previousValues.getCommitFrequencyWeekly();
        final float next = nextValues.getCommitFrequencyWeekly();
        if (previous == next) {
            return false;
        }

        final double magnitude = Math.max(Math.abs(previous), Math.abs(next));
        return Math.abs(next - previous) / magnitude >= COMMIT_FREQUENCY_RELATIVE_TOLERANCE;
    }
}
