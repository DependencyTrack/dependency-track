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
package org.dependencytrack.dex.engine.persistence.model;

/// Hint for the workflow task scheduler that a concurrency key experienced a change.
///
/// @param queueName      Name of the queue for which the concurrency key applies.
/// @param concurrencyKey The concurrency key that experienced a change.
/// @param freed          Whether the change was caused by a workflow run terminating,
///                       freeing the concurrency key for a new run.
public record ConcurrencyKeyWakeup(String queueName, String concurrencyKey, boolean freed) {
}
