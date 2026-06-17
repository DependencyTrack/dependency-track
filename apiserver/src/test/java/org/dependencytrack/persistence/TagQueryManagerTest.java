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
package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Tag;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class TagQueryManagerTest extends PersistenceCapableTest {

    @Test
    public void testTagIsCreated() {
        assertThat(qm.createTag("test-tag")).satisfies(
                tagCreated -> assertThat(tagCreated.getName()).isEqualTo("test-tag")
        );
    }

    @Test
    public void testShouldGetTagByName() {
        Tag tag = new Tag();
        tag.setName("test-tag");
        Tag result = qm.persist(tag);
        assertThat(qm.getTagByName(result.getName())).satisfies(
                tagFetched -> assertThat(tagFetched.getName()).isEqualTo("test-tag")
        );
    }

    @Test
    public void testShouldGetNullWhenTagNotPresent() {
        assertThat(qm.getTagByName("test-tag")).isNull();
    }

    @Test
    public void testTagsAreResolved() {

        // Resolve empty list of tags
        assertThat(qm.resolveTags(Collections.emptyList())).isEmpty();

        Tag tag1 = qm.createTag("test-tag-1");
        Tag tag2 = new Tag();
        tag2.setName("test-tag-2");

        assertThat(qm.resolveTags(List.of(tag1, tag2))).satisfiesExactlyInAnyOrder(
                tag -> assertThat(tag.getName()).isEqualTo(tag1.getName()),
                tag -> assertThat(tag.getName()).isEqualTo(tag2.getName())
        );

        // Update name of one tag and resolve again.
        tag1.setName("test-tag-updated");
        assertThat(qm.resolveTags(List.of(tag1, tag2))).satisfiesExactlyInAnyOrder(
                tag -> assertThat(tag.getName()).isEqualTo(tag1.getName()),
                tag -> assertThat(tag.getName()).isEqualTo(tag2.getName())
        );
    }

    @Test
    public void testTagsAreResolvedByName() {

        // Resolve empty list of tags
        assertThat(qm.resolveTagsByName(Collections.emptyList())).isEmpty();

        Tag tag1 = qm.createTag("test-tag-1");
        Tag tag2 = new Tag();
        tag2.setName("test-tag-2");

        assertThat(qm.resolveTagsByName(List.of("test-tag-1", "test-tag-2"))).satisfiesExactlyInAnyOrder(
                tag -> assertThat(tag.getName()).isEqualTo(tag1.getName()),
                tag -> assertThat(tag.getName()).isEqualTo(tag2.getName())
        );
    }
}
