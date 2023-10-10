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

/**
 * The response from VulnDB Vulnerability API will respond with 0 or more classifications.
 * This class defines the Classification objects returned.
 * Record created to replace the model class defined here: <a href="https://github.com/stevespringett/vulndb-data-mirror">...</a>
 */
public record Classification(int id, String name, String longname, String description, String mediumtext) {
}
