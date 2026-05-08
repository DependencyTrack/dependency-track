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
package org.dependencytrack.parser.spdx.expression;

import org.jspecify.annotations.Nullable;

import java.util.Locale;

import static java.util.Objects.requireNonNull;

/**
 * @param id      The license identifier (e.g. {@code "GPL-2.0"})
 * @param orLater Whether this represents an or-later range (from {@code +}
 *                operator or {@code -or-later} suffix)
 * @since 5.0.0
 */
record SpdxLicenseId(String id, boolean orLater) {

    SpdxLicenseId {
        requireNonNull(id, "id must not be null");
        if (id.toLowerCase(Locale.ROOT).endsWith("-or-later")) {
            id = id.substring(0, id.length() - "-or-later".length());
            orLater = true;
        }
    }

    static SpdxLicenseId of(String id) {
        return new SpdxLicenseId(id, false);
    }

    static @Nullable SpdxLicenseId of(SpdxExpression expr) {
        return switch (expr) {
            case SpdxExpression.Identifier it -> of(it.id());
            case SpdxExpression.OrLater it -> new SpdxLicenseId(it.license().id(), true);
            default -> null;
        };
    }

    boolean isEquivalentTo(SpdxLicenseId other) {
        requireNonNull(other, "other must not be null");

        final SpdxLicenseRegistry.Position thisPosition = SpdxLicenseRegistry.lookup(this.id);
        final SpdxLicenseRegistry.Position otherPosition = SpdxLicenseRegistry.lookup(other.id);

        if (thisPosition == null || otherPosition == null) {
            return this.id.equalsIgnoreCase(other.id);
        }

        return thisPosition.familyIndex() == otherPosition.familyIndex()
                && thisPosition.versionIndex() == otherPosition.versionIndex();
    }

    boolean isCompatibleWith(SpdxLicenseId other) {
        requireNonNull(other, "other must not be null");

        final SpdxLicenseRegistry.Position thisPosition = SpdxLicenseRegistry.lookup(this.id);
        final SpdxLicenseRegistry.Position otherPosition = SpdxLicenseRegistry.lookup(other.id);

        if (thisPosition == null || otherPosition == null) {
            return this.id.equalsIgnoreCase(other.id);
        }

        if (thisPosition.familyIndex() != otherPosition.familyIndex()) {
            return false;
        }

        if (thisPosition.versionIndex() == otherPosition.versionIndex()) {
            return true;
        }

        // other is or-later: this must be at or above other's base version.
        // If both are or-later, then same family is sufficient, as both cover
        // the highest version. e.g. GPL-1.0+ satisfies GPL-2.0+ because both cover GPL-3.0.
        if (other.orLater) {
            return this.orLater || thisPosition.versionIndex() >= otherPosition.versionIndex();
        }

        // this is or-later: other (an exact version) must be at or above this's base.
        // e.g. GPL-2.0+ satisfies GPL-3.0 because GPL-2.0+ covers GPL-3.0.
        if (this.orLater) {
            return otherPosition.versionIndex() >= thisPosition.versionIndex();
        }

        return false;
    }

}
