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
package org.dependencytrack.resources.v2.mapping;

import org.dependencytrack.api.v2.model.ComponentProject;
import org.dependencytrack.api.v2.model.DependencyMetrics;
import org.dependencytrack.api.v2.model.Hashes;
import org.dependencytrack.api.v2.model.License;
import org.dependencytrack.api.v2.model.OrganizationalContact;
import org.dependencytrack.api.v2.model.PackageArtifactMetadata;
import org.dependencytrack.api.v2.model.PackageMetadata;
import org.dependencytrack.api.v2.model.Scope;
import org.dependencytrack.api.v2.model.SortDirection;
import org.dependencytrack.model.Component;
import org.jspecify.annotations.Nullable;

import java.util.List;

public class ModelMapper {

    public static List<org.dependencytrack.model.OrganizationalContact> mapOrganizationalContacts(final List<OrganizationalContact> contacts) {
        return contacts.stream()
                .map(contact -> {
                    var mappedContact = new org.dependencytrack.model.OrganizationalContact();
                    mappedContact.setName(contact.getName());
                    mappedContact.setEmail(contact.getEmail());
                    mappedContact.setPhone(contact.getPhone());
                    return mappedContact;
                }).toList();
    }

    public static License mapLicense(org.dependencytrack.model.License license) {
        if (license == null) {
            return null;
        }
        return License.builder()
                .name(license.getName())
                .customLicense(license.isCustomLicense())
                .fsfLibre(license.isFsfLibre())
                .licenseId(license.getLicenseId())
                .osiApproved(license.isOsiApproved())
                .uuid(license.getUuid())
                .build();
    }

    public static ComponentProject mapProject(org.dependencytrack.model.Project project) {
        if (project == null) {
            return null;
        }
        return ComponentProject.builder()
                .name(project.getName())
                .version(project.getVersion())
                .uuid(project.getUuid())
                .build();
    }

    public static DependencyMetrics mapDependencyMetrics(org.dependencytrack.model.DependencyMetrics metrics) {
        if (metrics == null) {
            return null;
        }
        return DependencyMetrics.builder()
                .critical(metrics.getCritical())
                .high(metrics.getHigh())
                .medium(metrics.getMedium())
                .low(metrics.getLow())
                .unassigned(metrics.getUnassigned())
                .vulnerabilities(metrics.getVulnerabilities())
                .suppressed(metrics.getSuppressed())
                .findingsTotal(metrics.getFindingsTotal())
                .findingsAudited(metrics.getFindingsAudited())
                .findingsUnaudited(metrics.getFindingsUnaudited())
                .inheritedRiskScore(metrics.getInheritedRiskScore())
                .policyViolationsFail(metrics.getPolicyViolationsFail())
                .policyViolationsWarn(metrics.getPolicyViolationsWarn())
                .policyViolationsInfo(metrics.getPolicyViolationsInfo())
                .policyViolationsTotal(metrics.getPolicyViolationsTotal())
                .policyViolationsAudited(metrics.getPolicyViolationsAudited())
                .policyViolationsUnaudited(metrics.getPolicyViolationsUnaudited())
                .policyViolationsSecurityTotal(metrics.getPolicyViolationsSecurityTotal())
                .policyViolationsSecurityAudited(metrics.getPolicyViolationsSecurityAudited())
                .policyViolationsSecurityUnaudited(metrics.getPolicyViolationsSecurityUnaudited())
                .policyViolationsLicenseTotal(metrics.getPolicyViolationsLicenseTotal())
                .policyViolationsLicenseAudited(metrics.getPolicyViolationsLicenseAudited())
                .policyViolationsLicenseUnaudited(metrics.getPolicyViolationsLicenseUnaudited())
                .policyViolationsOperationalTotal(metrics.getPolicyViolationsOperationalTotal())
                .policyViolationsOperationalAudited(metrics.getPolicyViolationsOperationalAudited())
                .policyViolationsOperationalUnaudited(metrics.getPolicyViolationsOperationalUnaudited())
                .build();
    }

    public static Hashes mapHashes(Component component) {
        boolean hasAnyHash = component.getMd5() != null
                || component.getSha1() != null
                || component.getSha256() != null
                || component.getSha384() != null
                || component.getSha512() != null
                || component.getSha3_256() != null
                || component.getSha3_384() != null
                || component.getSha3_512() != null
                || component.getBlake2b_256() != null
                || component.getBlake2b_384() != null
                || component.getBlake2b_512() != null
                || component.getBlake3() != null;

        if (!hasAnyHash) {
            return null;
        }

        return Hashes.builder()
                .md5(component.getMd5())
                .sha1(component.getSha1())
                .sha256(component.getSha256())
                .sha384(component.getSha384())
                .sha512(component.getSha512())
                .sha3256(component.getSha3_256())
                .sha3384(component.getSha3_384())
                .sha3512(component.getSha3_512())
                .blake2b256(component.getBlake2b_256())
                .blake2b384(component.getBlake2b_384())
                .blake2b512(component.getBlake2b_512())
                .blake3(component.getBlake3())
                .build();
    }

    public static Scope mapScope(org.dependencytrack.model.Scope componentScope) {
        if (componentScope == null) {
            return null;
        }
        return switch (componentScope) {
            case EXCLUDED -> Scope.EXCLUDED;
            case OPTIONAL -> Scope.OPTIONAL;
            case REQUIRED -> Scope.REQUIRED;
        };
    }

    public static org.dependencytrack.common.pagination.@Nullable SortDirection mapSortDirection(
            @Nullable SortDirection sortDirection) {
        return switch (sortDirection) {
            case ASC -> org.dependencytrack.common.pagination.SortDirection.ASC;
            case DESC -> org.dependencytrack.common.pagination.SortDirection.DESC;
            case null -> null;
        };
    }

    public static PackageMetadata map(org.dependencytrack.model.@Nullable PackageMetadata pm) {
        if (pm == null) {
            return null;
        }

        return PackageMetadata.builder()
                .latestVersion(pm.latestVersion())
                .latestVersionPublishedAt(pm.latestVersionPublishedAt() != null
                        ? pm.latestVersionPublishedAt().toEpochMilli()
                        : null)
                .resolvedAt(pm.resolvedAt().toEpochMilli())
                .build();
    }

    public static PackageArtifactMetadata map(org.dependencytrack.model.@Nullable PackageArtifactMetadata pam) {
        if (pam == null) {
            return null;
        }

        return PackageArtifactMetadata.builder()
                .hashes(mapHashes(pam))
                .publishedAt(pam.publishedAt() != null
                        ? pam.publishedAt().toEpochMilli()
                        : null)
                .resolvedFrom(pam.resolvedFrom())
                .resolvedAt(pam.resolvedAt() != null
                        ? pam.resolvedAt().toEpochMilli()
                        : null)
                .build();
    }

    private static Hashes mapHashes(org.dependencytrack.model.PackageArtifactMetadata pam) {
        if (pam.md5() == null
                && pam.sha1() == null
                && pam.sha256() == null
                && pam.sha512() == null) {
            return null;
        }

        return Hashes.builder()
                .md5(pam.md5())
                .sha1(pam.sha1())
                .sha256(pam.sha256())
                .sha512(pam.sha512())
                .build();
    }

}
