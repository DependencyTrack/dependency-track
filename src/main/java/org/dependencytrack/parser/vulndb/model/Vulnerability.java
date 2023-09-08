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
package org.dependencytrack.parser.vulndb.model;

import java.util.List;

/**
 * The response from VulnDB Vulnerability API will respond with 0 or more vulnerabilities.
 * This record defines the Vulnerability objects returned.
 * Record created to replace the model class defined here: <a href="https://github.com/stevespringett/vulndb-data-mirror">...</a>
 */
public record Vulnerability(int id,
                            String title,
                            String disclosureDate,
                            String discoveryDate,
                            String exploitPublishDate,
                            String keywords,
                            String shortDescription,
                            String description,
                            String solution,
                            String manualNotes,
                            String technicalDescription,
                            String solutionDate,
                            String vendorInformedDate,
                            String vendorAckDate,
                            String thirdPartySolutionDate,
                            List<Classification> classifications,
                            List<Author> authors,
                            List<ExternalReference> extReferences,
                            List<ExternalText> extTexts,
                            List<Vendor> vendors,
                            List<CvssV2Metric> cvssV2Metrics,
                            List<CvssV3Metric> cvssV3Metrics,
                            NvdAdditionalInfo nvdAdditionalInfo) implements ApiObject {
}
