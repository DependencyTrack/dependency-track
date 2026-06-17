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
package org.dependencytrack.model.mapping;

import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;

import java.math.BigDecimal;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.dependencytrack.util.PersistenceUtil.assertNonPersistent;

/**
 * Utility class to map objects from Dependency-Track's internal data model to Policy protocol buffers.
 */
public class PolicyProtoMapper {

    public static org.dependencytrack.proto.policy.v1.Component mapToProto(final Component component) {
        if (component == null) {
            return org.dependencytrack.proto.policy.v1.Component.getDefaultInstance();
        }

        // An object attached to a persistence context could do lazy loading of fields when accessing them.
        // Ensure this can't happen, as it could cause massive performance degradation.
        assertNonPersistent(component, "component must not be persistent");

        final org.dependencytrack.proto.policy.v1.Component.Builder protoBuilder =
                org.dependencytrack.proto.policy.v1.Component.newBuilder();
        maybeSet(asString(component.getUuid()), protoBuilder::setUuid);
        maybeSet(component::getGroup, protoBuilder::setGroup);
        maybeSet(component::getName, protoBuilder::setName);
        maybeSet(component::getVersion, protoBuilder::setVersion);
        maybeSet(asString(component.getClassifier()), protoBuilder::setClassifier);
        maybeSet(component::getCpe, protoBuilder::setCpe);
        maybeSet(component::getPurl, purl -> protoBuilder.setPurl(purl.canonicalize()));
        maybeSet(component::getSwidTagId, protoBuilder::setSwidTagId);
        maybeSet(component::isInternal, protoBuilder::setIsInternal);
        maybeSet(component::getMd5, protoBuilder::setMd5);
        maybeSet(component::getSha1, protoBuilder::setSha1);
        maybeSet(component::getSha256, protoBuilder::setSha256);
        maybeSet(component::getSha384, protoBuilder::setSha384);
        maybeSet(component::getSha512, protoBuilder::setSha512);
        maybeSet(component::getSha3_256, protoBuilder::setSha3256);
        maybeSet(component::getSha3_384, protoBuilder::setSha3384);
        maybeSet(component::getSha3_512, protoBuilder::setSha3512);
        maybeSet(component::getBlake2b_256, protoBuilder::setBlake2B256);
        maybeSet(component::getBlake2b_384, protoBuilder::setBlake2B384);
        maybeSet(component::getBlake2b_512, protoBuilder::setBlake2B512);
        maybeSet(component::getBlake3, protoBuilder::setBlake3);
        maybeSet(component::getResolvedLicense, license -> protoBuilder.setResolvedLicense(mapToProto(license)));

        return protoBuilder.build();
    }

    public static org.dependencytrack.proto.policy.v1.Vulnerability mapToProto(final Vulnerability vuln) {
        if (vuln == null) {
            return org.dependencytrack.proto.policy.v1.Vulnerability.getDefaultInstance();
        }

        // An object attached to a persistence context could do lazy loading of fields when accessing them.
        // Ensure this can't happen, as it could cause massive performance degradation.
        assertNonPersistent(vuln, "vuln must not be persistent");

        final org.dependencytrack.proto.policy.v1.Vulnerability.Builder protoBuilder =
                org.dependencytrack.proto.policy.v1.Vulnerability.newBuilder();
        maybeSet(asString(vuln.getUuid()), protoBuilder::setUuid);
        maybeSet(vuln::getVulnId, protoBuilder::setId);
        maybeSet(vuln::getSource, protoBuilder::setSource);
        maybeSet(() -> vuln.getAliases() != null
                        ? vuln.getAliases().stream().flatMap(PolicyProtoMapper::mapToProtos).distinct().toList()
                        : Collections.emptyList(),
                protoBuilder::addAllAliases);
        maybeSet(vuln::getCwes, protoBuilder::addAllCwes);
        maybeSet(asTimestamp(vuln.getCreated()), protoBuilder::setCreated);
        maybeSet(asTimestamp(vuln.getPublished()), protoBuilder::setPublished);
        maybeSet(asTimestamp(vuln.getUpdated()), protoBuilder::setUpdated);
        maybeSet(asString(vuln.getSeverity()), protoBuilder::setSeverity);
        maybeSet(asDouble(vuln.getCvssV2BaseScore()), protoBuilder::setCvssv2BaseScore);
        maybeSet(asDouble(vuln.getCvssV2ImpactSubScore()), protoBuilder::setCvssv2ImpactSubscore);
        maybeSet(asDouble(vuln.getCvssV2ExploitabilitySubScore()), protoBuilder::setCvssv2ExploitabilitySubscore);
        maybeSet(vuln::getCvssV2Vector, protoBuilder::setCvssv2Vector);
        maybeSet(asDouble(vuln.getCvssV3BaseScore()), protoBuilder::setCvssv3BaseScore);
        maybeSet(asDouble(vuln.getCvssV3ImpactSubScore()), protoBuilder::setCvssv3ImpactSubscore);
        maybeSet(asDouble(vuln.getCvssV3ExploitabilitySubScore()), protoBuilder::setCvssv3ExploitabilitySubscore);
        maybeSet(vuln::getCvssV3Vector, protoBuilder::setCvssv3Vector);
        maybeSet(asDouble(vuln.getCvssV4Score()), protoBuilder::setCvssv4Score);
        maybeSet(vuln::getCvssV4Vector, protoBuilder::setCvssv4Vector);
        maybeSet(asDouble(vuln.getOwaspRRBusinessImpactScore()), protoBuilder::setOwaspRrBusinessImpactScore);
        maybeSet(asDouble(vuln.getOwaspRRLikelihoodScore()), protoBuilder::setOwaspRrLikelihoodScore);
        maybeSet(asDouble(vuln.getOwaspRRTechnicalImpactScore()), protoBuilder::setOwaspRrTechnicalImpactScore);
        maybeSet(vuln::getOwaspRRVector, protoBuilder::setOwaspRrVector);
        maybeSet(asDouble(vuln.getEpssScore()), protoBuilder::setEpssScore);
        maybeSet(asDouble(vuln.getEpssPercentile()), protoBuilder::setEpssPercentile);
        return protoBuilder.build();
    }

    private static org.dependencytrack.proto.policy.v1.License mapToProto(final License license) {
        if (license == null) {
            return org.dependencytrack.proto.policy.v1.License.getDefaultInstance();
        }

        // An object attached to a persistence context could do lazy loading of fields when accessing them.
        // Ensure this can't happen, as it could cause massive performance degradation.
        assertNonPersistent(license, "license must not be persistent");

        final org.dependencytrack.proto.policy.v1.License.Builder protoBuilder =
                org.dependencytrack.proto.policy.v1.License.newBuilder();
        maybeSet(asString(license.getUuid()), protoBuilder::setUuid);
        maybeSet(license::getLicenseId, protoBuilder::setId);
        maybeSet(license::getName, protoBuilder::setName);
        maybeSet(license::isOsiApproved, protoBuilder::setIsOsiApproved);
        maybeSet(license::isFsfLibre, protoBuilder::setIsFsfLibre);
        maybeSet(license::isDeprecatedLicenseId, protoBuilder::setIsDeprecatedId);
        maybeSet(license::isCustomLicense, protoBuilder::setIsCustom);
        maybeSet(license::getLicenseGroups, licenseGroups -> licenseGroups.stream()
                .map(PolicyProtoMapper::mapToProto).forEach(protoBuilder::addGroups));

        return protoBuilder.build();
    }

    private static org.dependencytrack.proto.policy.v1.License.Group mapToProto(final LicenseGroup licenseGroup) {
        if (licenseGroup == null) {
            return org.dependencytrack.proto.policy.v1.License.Group.getDefaultInstance();
        }

        // An object attached to a persistence context could do lazy loading of fields when accessing them.
        // Ensure this can't happen, as it could cause massive performance degradation.
        assertNonPersistent(licenseGroup, "licenseGroup must not be persistent");

        final org.dependencytrack.proto.policy.v1.License.Group.Builder protoBuilder =
                org.dependencytrack.proto.policy.v1.License.Group.newBuilder();
        maybeSet(asString(licenseGroup.getUuid()), protoBuilder::setUuid);
        maybeSet(licenseGroup::getName, protoBuilder::setName);
        return protoBuilder.build();
    }

    private static Stream<org.dependencytrack.proto.policy.v1.Vulnerability.Alias> mapToProtos(final VulnerabilityAlias alias) {
        if (alias == null) {
            return Stream.empty();
        }

        // An object attached to a persistence context could do lazy loading of fields when accessing them.
        // Ensure this can't happen, as it could cause massive performance degradation.
        assertNonPersistent(alias, "alias must not be persistent");

        return alias.getAllBySource().entrySet().stream()
                .map(aliasEntry -> org.dependencytrack.proto.policy.v1.Vulnerability.Alias.newBuilder()
                        .setSource(aliasEntry.getKey().name())
                        .setId(aliasEntry.getValue())
                        .build());
    }

    private static <V> void maybeSet(final Supplier<V> getter, final Consumer<V> setter) {
        final V modelValue = getter.get();
        if (modelValue == null) {
            return;
        }

        setter.accept(modelValue);
    }

    private static Supplier<Double> asDouble(final BigDecimal bigDecimal) {
        return () -> bigDecimal != null ? bigDecimal.doubleValue() : null;
    }

    private static Supplier<String> asString(final Enum<?> enumInstance) {
        return () -> enumInstance != null ? enumInstance.name() : null;
    }

    private static Supplier<String> asString(final UUID uuid) {
        return () -> uuid != null ? uuid.toString() : null;
    }

    private static Supplier<Timestamp> asTimestamp(final Date date) {
        return () -> date != null ? Timestamps.fromDate(date) : null;
    }

}
