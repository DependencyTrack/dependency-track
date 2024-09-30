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
package org.dependencytrack.persistence.converter;

import org.dependencytrack.model.OrganizationalContact;
import org.junit.Test;

import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class OrganizationalContactsJsonConverterTest {

    @Test
    public void testConvertToDatastore() {
        final var contact = new OrganizationalContact();
        contact.setName("Foo");
        contact.setEmail("foo@example.com");
        contact.setPhone("123456789");

        assertThatJson(new OrganizationalContactsJsonConverter().convertToDatastore(List.of(contact)))
                .isEqualTo("""
                        [
                          {
                            "name": "Foo",
                            "email": "foo@example.com",
                            "phone": "123456789"
                          }
                        ]
                        """);
    }

    @Test
    public void testConvertToAttribute() {
        final List<OrganizationalContact> contacts = new OrganizationalContactsJsonConverter().convertToAttribute("""
                [
                  {
                    "name": "Foo",
                    "email": "foo@example.com",
                    "phone": "123456789"
                  }
                ]
                """);

        assertThat(contacts).satisfiesExactly(contact -> {
            assertThat(contact.getName()).isEqualTo("Foo");
            assertThat(contact.getEmail()).isEqualTo("foo@example.com");
            assertThat(contact.getPhone()).isEqualTo("123456789");
        });
    }

    @Test
    public void testConvertToDatastoreNull() {
        assertThat(new OrganizationalContactsJsonConverter().convertToDatastore(null)).isNull();
    }

    @Test
    public void testConvertToAttributeNull() {
        assertThat(new OrganizationalContactsJsonConverter().convertToAttribute(null)).isNull();
    }

}