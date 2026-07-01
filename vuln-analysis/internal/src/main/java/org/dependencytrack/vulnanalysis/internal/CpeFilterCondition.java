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
package org.dependencytrack.vulnanalysis.internal;

import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;

record CpeFilterCondition(CpeAttribute attribute, Operator operator, @Nullable String value) {

    private enum Operator {

        EQUALS("="),
        IS_NOT("IS NOT");

        private final String sql;

        Operator(final String sql) {
            this.sql = sql;
        }

    }

    String toSql(String parameterName) {
        return value != null
                ? "\"%s\" %s :%s".formatted(attribute, operator.sql, parameterName)
                : "\"%s\" %s NULL".formatted(attribute, operator.sql);
    }

    static List<CpeFilterCondition> of(CpeAttribute attribute, String attributeValue) {
        final var conditions = new ArrayList<CpeFilterCondition>();

        // The query composition below represents a partial implementation of the CPE
        // matching logic. It makes references to table 6-2 of the CPE name matching
        // specification: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf
        //
        // In CPE matching terms, the parameters of this method represent the target,
        // and the `VulnerableSoftware`s in the database represent the source.
        //
        // While the source *can* contain wildcards ("*", "?"), there is currently (Oct. 2023)
        // no occurrence of part, vendor, or product with wildcards in the NVD database.
        // Evaluating wildcards in the source can only be done in-memory. If we wanted to do that,
        // we'd have to fetch *all* records, which is not practical.

        if (!"*".equals(attributeValue) && !"-".equals(attributeValue)) {
            // | No. | Source A-V      | Target A-V | Relation             |
            // | :-- | :-------------- | :--------- | :------------------- |
            // | 3   | ANY             | i          | SUPERSET             |
            // | 7   | NA              | i          | DISJOINT             |
            // | 9   | i               | i          | EQUAL                |
            // | 10  | i               | k          | DISJOINT             |
            // | 14  | m1 + wild cards | m2         | SUPERSET or DISJOINT |
            conditions.add(new CpeFilterCondition(attribute, CpeFilterCondition.Operator.EQUALS, "*"));
            conditions.add(new CpeFilterCondition(attribute, CpeFilterCondition.Operator.EQUALS, attributeValue));

            // NOTE: Target *could* include wildcard, but the relation
            // for those cases is undefined:
            //
            // | No. | Source A-V      | Target A-V      | Relation   |
            // | :-- | :-------------- | :-------------- | :--------- |
            // | 4   | ANY             | m + wild cards  | undefined  |
            // | 8   | NA              | m + wild cards  | undefined  |
            // | 11  | i               | m + wild cards  | undefined  |
            // | 17  | m1 + wild cards | m2 + wild cards | undefined  |
        } else if ("-".equals(attributeValue)) {
            // | No. | Source A-V     | Target A-V | Relation |
            // | :-- | :------------- | :--------- | :------- |
            // | 2   | ANY            | NA         | SUPERSET |
            // | 6   | NA             | NA         | EQUAL    |
            // | 12  | i              | NA         | DISJOINT |
            // | 16  | m + wild cards | NA         | DISJOINT |
            conditions.add(new CpeFilterCondition(attribute, CpeFilterCondition.Operator.EQUALS, "*"));
            conditions.add(new CpeFilterCondition(attribute, CpeFilterCondition.Operator.EQUALS, "-"));
        } else {
            // | No. | Source A-V     | Target A-V | Relation |
            // | :-- | :------------- | :--------- | :------- |
            // | 1   | ANY            | ANY        | EQUAL    |
            // | 5   | NA             | ANY        | SUBSET   |
            // | 13  | i              | ANY        | SUBSET   |
            // | 15  | m + wild cards | ANY        | SUBSET   |
            conditions.add(new CpeFilterCondition(attribute, CpeFilterCondition.Operator.IS_NOT, null));
        }

        return conditions;
    }

}
