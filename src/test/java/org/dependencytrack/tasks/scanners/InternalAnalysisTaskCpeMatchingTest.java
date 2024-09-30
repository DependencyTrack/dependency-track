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
package org.dependencytrack.tasks.scanners;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.InternalAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.nvd.ModelConverter;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED;
import static org.dependencytrack.tasks.scanners.InternalAnalysisTaskCpeMatchingTest.Range.withRange;

@RunWith(Parameterized.class)
public class InternalAnalysisTaskCpeMatchingTest extends PersistenceCapableTest {

    @Parameters(name = "{index} source={0}, target={3}, range={1}, expectMatch={2}")
    public static Collection<Object[]> parameters() {
        return Arrays.asList(new Object[][]{
                // | No. | Source A-V | Target A-V | Relation |
                // | :-- | :--------- | :--------- | :------- |
                // | 1   | ANY        | ANY        | EQUAL    |
                {"cpe:2.3:*:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:*:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:*:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:*:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:*:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:*:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:*:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:*:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:*:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:*:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:*"},
                // | No. | Source A-V | Target A-V | Relation |
                // | :-- | :--------- | :--------- | :------- |
                // | 2   | ANY        | NA         | SUPERSET |
                {"cpe:2.3:*:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:-:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:-:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:-:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:-:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:-:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:-:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:*:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:-:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:*:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:-:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:*:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:-:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:-"},
                // | No. | Source A-V | Target A-V | Relation |
                // | :-- | :--------- | :--------- | :------- |
                // | 3   | ANY        | i          | SUPERSET |
                {"cpe:2.3:*:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:*:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:*:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:*:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                // | No. | Source A-V | Target A-V     | Relation   |
                // | :-- | :--------- | :------------- | :--------- |
                // | 4   | ANY        | m + wild cards | undefined  |
                // {"cpe:2.3:*:vendor:product:1.0.0:*:*:*:*:*:*:*", MATCHES, "cpe:2.3:?:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                //   cpe-parser library does not allow wildcards for the part attribute.
                {"cpe:2.3:a:*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:*:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:*:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:*:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*"},
                // | No. | Source A-V | Target A-V | Relation |
                // | :-- | :--------- | :--------- | :------- |
                // | 5   | NA         | ANY        | SUBSET   |
                {"cpe:2.3:-:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:*:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:-:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:-:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:-:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:-:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:*:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:-:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:*:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:-:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:*:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:-:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:*:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:-:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:*:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:-", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:*"},
                // | No. | Source A-V | Target A-V | Relation |
                // | :-- | :--------- | :--------- | :------- |
                // | 6   | NA         | NA         | EQUAL    |
                {"cpe:2.3:-:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:-:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:-:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:-:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:-:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:-:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:-:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:-:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:-:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:-:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:-:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:-:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:-:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:-:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:-:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:-:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:-:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:-:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:-", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:-"},
                // | No. | Source A-V | Target A-V | Relation |
                // | :-- | :--------- | :--------- | :------- |
                // | 7   | NA         | i          | DISJOINT |
                {"cpe:2.3:-:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:-:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:-:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:-:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:-:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:-:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:-:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:-:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:-:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:-", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                // | No. | Source A-V | Target A-V      | Relation   |
                // | :-- | :--------- | :-------------- | :--------- |
                // | 8   | NA         | m + wild cards  | undefined  |
                // {"cpe:2.3:-:vendor:product:1.0.0:*:*:*:*:*:*:*", DOES_NOT_MATCH, "cpe:2.3:?:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                //   cpe-parser library does not allow wildcards for the part attribute.
                {"cpe:2.3:a:-:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:-:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:-:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:-:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:-:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:-:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:-:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:-:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:-", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*"},
                // | No. | Source A-V | Target A-V | Relation |
                // | :-- | :--------- | :--------- | :------- |
                // | 9   | i          | i          | EQUAL    |
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                // | No. | Source A-V | Target A-V | Relation |
                // | :-- | :--------- | :--------- | :------- |
                // | 10  | i          | k          | DISJOINT |
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:o:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:rodnev:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:tcudorp:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:0.0.1:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:etadpu:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:noitide:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:gnal:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:noitidEws:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:wStegrat:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:wHtegrat:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:rehto"},
                // | No. | Source A-V | Target A-V      | Relation   |
                // | :-- | :--------- | :-------------- | :--------- |
                // | 11  | i          | m + wild cards  | undefined  |
                // {"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*", DOES_NOT_MATCH, "cpe:2.3:?:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                //   cpe-parser library does not allow wildcards for the part attribute.
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*"},
                // | No. | Source A-V | Target A-V | Relation |
                // | :-- | :--------- | :--------- | :------- |
                // | 12  | i          | NA         | DISJOINT |
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:-:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:-:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:-:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:-:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:-:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:-:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:-:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:-:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:-:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:-"},
                // | No. | Source A-V     | Target A-V | Relation |
                // | :-- | :------------- | :--------- | :------- |
                // | 13  | i              | ANY        | SUPERSET |
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:*:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:*:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:*:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:*:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:*:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:*:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:*"},
                // | No. | Source A-V      | Target A-V | Relation             |
                // | :-- | :-------------- | :--------- | :------------------- |
                // | 14  | m1 + wild cards | m2         | SUPERSET or DISJOINT |
                // {"cpe:2.3:?:vendor:product:1.0.0:*:*:*:*:*:*:*", DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                //   cpe-parser library does not allow wildcards for the part attribute.
                {"cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                //   wildcard expansion in source vendor is currently not supported; *should* be SUPERSET.
                {"cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                //   wildcard expansion in source product is currently not supported; *should* be SUPERSET.
                {"cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                // | No. | Source A-V     | Target A-V | Relation |
                // | :-- | :------------- | :--------- | :------- |
                // | 15  | m + wild cards | ANY        | SUPERSET |
                // {"cpe:2.3:?:vendor:product:1.0.0:*:*:*:*:*:*:*", DOES_NOT_MATCH, "cpe:2.3:*:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                //   cpe-parser library does not allow wildcards for the part attribute.
                {"cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:*:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:*:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:*:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:*:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:*:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:*"},
                // | No. | Source A-V     | Target A-V | Relation |
                // | :-- | :------------- | :--------- | :------- |
                // | 16  | m + wild cards | NA         | DISJOINT |
                // {"cpe:2.3:?:vendor:product:1.0.0:*:*:*:*:*:*:*", DOES_NOT_MATCH, "cpe:2.3:-:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                //   cpe-parser library does not allow wildcards for the part attribute.
                {"cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:-:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:-:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:-:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:-:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:-:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:-:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:-:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:-:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:-"},
                // | No. | Source A-V      | Target A-V      | Relation   |
                // | :-- | :-------------- | :-------------- | :--------- |
                // | 17  | m1 + wild cards | m2 + wild cards | undefined  |
                // {"cpe:2.3:?:vendor:product:1.0.0:*:*:*:*:*:*:*", DOES_NOT_MATCH, "cpe:2.3:?:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                //   cpe-parser library does not allow wildcards for the part attribute.
                {"cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*"},
                {"cpe:2.3:a:ven*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:v*:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:pro*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:p*:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.*:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1*:update:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:upd*:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:u*:edition:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edi*:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:e*:lang:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:la*:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:l*:swEdition:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdi*:targetSw:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:s*:targetSw:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:tar*:targetHw:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:t*:targetHw:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:tar*:other", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:t*:other"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:oth*", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:o*"},
                // ---
                // Version range evaluation
                // ---
                {"cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingStartIncluding("1.0.0"), MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                {"cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingStartExcluding("1.0.0"), DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                {"cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingStartIncluding("0.9.9"), MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                {"cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingStartExcluding("0.9.9"), MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                {"cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingStartIncluding("1.0.0"), DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                {"cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingEndIncluding("1.0.0"), MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                {"cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingEndExcluding("1.0.0"), DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                {"cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingEndIncluding("1.0.1"), MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                {"cpe:2.3:a:vendor:product:*:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingEndExcluding("1.0.1"), MATCHES, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                {"cpe:2.3:a:vendor:product:-:update:edition:lang:swEdition:targetSw:targetHw:other", withRange().havingEndIncluding("1.0.0"), DOES_NOT_MATCH, "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
                // ---
                // Required CPE name comparison relations (as per table 6-4 in the spec)
                // ---
                // Scenario:  All attributes are EQUAL
                {"cpe:2.3:*:*:*:*:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:*:*:*:*:*:*:*:*:*:*:*"},
                {"cpe:2.3:-:-:-:-:-:-:-:-:-:-:-", WITHOUT_RANGE, MATCHES, "cpe:2.3:-:-:-:-:-:-:-:-:-:-:-"},
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                // Scenario:  All attributes of source are SUPERSET of target
                {"cpe:2.3:*:*:*:*:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other"},
                // Scenario:  All attributes of source are SUBSET of target
                {"cpe:2.3:a:vendor:product:1.0.0:update:edition:lang:swEdition:targetSw:targetHw:other", WITHOUT_RANGE, MATCHES, "cpe:2.3:*:*:*:*:*:*:*:*:*:*:*"},
                // ---
                // Regression tests
                // ---
                // Issue:     https://github.com/DependencyTrack/dependency-track/issues/1320
                // Scenario:  "product" of source is "2000e_firmware", "version" of target is "2000e_firmware" -> EQUAL.
                //            "version" of source is NA, "version" of target is NA -> EQUAL.
                // Table No.: 6, 9
                {"cpe:2.3:o:intel:2000e_firmware:-:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:o:intel:2000e_firmware:-:*:*:*:*:*:*:*"},
                // Scenario:  "version" of source is ANY, "version" of target is "2000e" -> SUPERSET.
                //            "update" of source is ANY, "update" of target is NA -> SUPERSET.
                // Table No.: 3, 2
                {"cpe:2.3:h:intel:*:*:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:h:intel:2000e:-:*:*:*:*:*:*:*"},
                // ---
                // Issue:     https://github.com/DependencyTrack/dependency-track/issues/1832
                // Scenario:  "version" of source is NA, "version" of target is "2.4.54" -> DISJOINT.
                // Table No.: 7
                {"cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*"},
                // Scenario:  "version" of source is NA, "version" of target is ANY -> SUBSET.
                // Table No.: 5
                {"cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"},
                // ---
                // Issue:     https://github.com/DependencyTrack/dependency-track/issues/2188
                // Scenario:  "update" of source is NA, "update" of target is ANY -> SUBSET.
                // Table No.: 5
                {"cpe:2.3:a:xiph:speex:1.2:-:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:a:xiph:speex:1.2:*:*:*:*:*:*:*"},
                // ---
                // Issue:     https://github.com/DependencyTrack/dependency-track/issues/2580
                // Scenario:  "vendor" of source is "linux", "vendor" of target ANY -> SUBSET.
                // Table No.: 13
                {"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:o:*:linux_kernel:*:*:*:*:*:*:*:*"},
                {"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:o:*:linux_kernel:4.19.139:*:*:*:*:*:*:*"},
                // ---
                // Issue:     https://github.com/DependencyTrack/dependency-track/issues/2894
                // Scenario:  "vendor" and "product" with different casing -> EQUAL.
                // Table No.: 9
                // Note:      CPEs with uppercase "part" are considered invalid by the cpe-parser library.
                // TODO:      This should match, but can't currently support this as it would require an function index on UPPER("PART"),
                //            UPPER("VENDOR"), and UPPER("PRODUCT"), which we cannot add through JDO annotations.
                {"cpe:2.3:o:lInUx:lInUx_KeRnEl:5.15.37:*:*:*:*:*:*:*", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:o:LiNuX:LiNuX_kErNeL:5.15.37:*:*:*:*:*:*:*"},
                // ---
                // Issue:     https://github.com/DependencyTrack/dependency-track/issues/2988
                // Scenario:  "other" attribute of source is NA, "other" attribute of target is ANY -> SUBSET.
                // Table No.: 5
                {"cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:*:NA", WITHOUT_RANGE, MATCHES, "cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:*:*"},
                // Scenario:  "target_hw" of source if x64, "target_hw" of target is ANY -> SUBSET.
                // Table No.: 13
                {"cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:x86:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:o:linux:linux_kernel:5.15.37:*:*:*:*:*:*:*"},
                // Scenario:  "vendor" of source contains wildcard, "vendor" of target is ANY -> SUBSET.
                // Table No.: 15
                {"cpe:2.3:o:linu*:linux_kernel:5.15.37:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:o:*:linux_kernel:5.15.37:*:*:*:*:*:*:*"},
                // ---
                // Issue:     https://github.com/DependencyTrack/dependency-track/issues/2994
                // Scenario:  "part" of source is "a", "part" of target is ANY -> SUBSET.
                // Table No.: 13
                {"cpe:2.3:a:busybox:busybox:1.34.1:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:*:busybox:busybox:1.34.1:*:*:*:*:*:*:*"},
                // ---
                // Issue:     https://github.com/DependencyTrack/dependency-track/pull/1929#issuecomment-1759411976
                // Scenario:  "part" and "vendor" of source are i, "part" and "vendor" of target are ANY -> SUBSET
                // Table No.: 13
                {"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:*:*:nginx:*:*:*:*:*:*:*:*"},
                {"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", withRange().havingEndExcluding("1.21.0"), MATCHES, "cpe:2.3:*:*:nginx:*:*:*:*:*:*:*:*"},
                // Scenario:  Same as above, but "version" of target is i, which evaluates to SUPERSET for the "version" attribute
                // Table No.: 3, 13
                {"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", WITHOUT_RANGE, MATCHES, "cpe:2.3:*:*:nginx:1.20.1:*:*:*:*:*:*:*"},
                {"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", withRange().havingEndExcluding("1.21.0"), MATCHES, "cpe:2.3:*:*:nginx:1.20.1:*:*:*:*:*:*:*"},
                // ---
                // Issue:     https://github.com/DependencyTrack/dependency-track/issues/3178#issuecomment-1812809295
                // Scenario:  "vendor" of source is i, "product" of source is ANY, "vendor" of target is ANY, "product" of target is i
                //            We consider mixed SUBSET and SUPERSET relations in "vendor" and "product" attributes to be ambiguous and treat them as no-match
                // Table No.: 3, 13
                {"cpe:2.3:a:pascom_cloud_phone_system:*:*:*:*:*:*:*:*:*", WITHOUT_RANGE, DOES_NOT_MATCH, "cpe:2.3:a:*:util-linux-setarch:2.37.4:*:*:*:*:*:*:*"}
        });
    }

    public record Range(String startIncluding, String startExcluding, String endIncluding, String endExcluding) {

        public static Range withRange() {
            return new Range(null, null, null, null);
        }

        public Range havingStartIncluding(final String startIncluding) {
            return new Range(startIncluding, this.startExcluding, this.endIncluding, this.endExcluding);
        }

        public Range havingStartExcluding(final String startExcluding) {
            return new Range(this.startIncluding, startExcluding, this.endIncluding, this.endExcluding);
        }

        public Range havingEndIncluding(final String endIncluding) {
            return new Range(this.startIncluding, this.startExcluding, endIncluding, this.endExcluding);
        }

        public Range havingEndExcluding(final String endExcluding) {
            return new Range(this.startIncluding, this.startExcluding, this.endIncluding, endExcluding);
        }

    }

    private static final boolean MATCHES = true;
    private static final boolean DOES_NOT_MATCH = false;
    private static final Range WITHOUT_RANGE = null;

    private final String sourceCpe;
    private final Range sourceRange;
    private final boolean expectMatch;
    private final String targetCpe;

    public InternalAnalysisTaskCpeMatchingTest(final String sourceCpe, final Range sourceRange,
                                               final boolean expectMatch, final String targetCpe) {
        this.sourceCpe = sourceCpe;
        this.sourceRange = sourceRange;
        this.expectMatch = expectMatch;
        this.targetCpe = targetCpe;
    }

    @Before
    public void setUp() {
        qm.createConfigProperty(
                SCANNER_INTERNAL_ENABLED.getGroupName(),
                SCANNER_INTERNAL_ENABLED.getPropertyName(),
                "true",
                SCANNER_INTERNAL_ENABLED.getPropertyType(),
                SCANNER_INTERNAL_ENABLED.getDescription()
        );
    }

    @Test
    public void test() throws Exception {
        final VulnerableSoftware vs = ModelConverter.convertCpe23UriToVulnerableSoftware(sourceCpe);
        if (sourceRange != null) {
            Optional.ofNullable(sourceRange.startIncluding).ifPresent(vs::setVersionStartIncluding);
            Optional.ofNullable(sourceRange.startExcluding).ifPresent(vs::setVersionStartExcluding);
            Optional.ofNullable(sourceRange.endIncluding).ifPresent(vs::setVersionEndIncluding);
            Optional.ofNullable(sourceRange.endExcluding).ifPresent(vs::setVersionEndExcluding);
        }
        vs.setVulnerable(true);
        qm.persist(vs);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-123");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setVulnerableSoftware(List.of(vs));
        qm.persist(vuln);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setCpe(targetCpe);
        qm.persist(component);

        new InternalAnalysisTask().inform(new InternalAnalysisEvent(qm.detach(Component.class, component.getId())));

        if (expectMatch) {
            assertThat(qm.getAllVulnerabilities(component)).hasSize(1);
        } else {
            assertThat(qm.getAllVulnerabilities(component)).isEmpty();
        }
    }

}
