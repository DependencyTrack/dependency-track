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
package org.dependencytrack.support.datanucleus.method;

import org.dependencytrack.support.datanucleus.AbstractTest;
import org.dependencytrack.support.datanucleus.test.Person;
import org.junit.jupiter.api.Test;
import org.postgresql.util.PSQLException;

import javax.jdo.JDOException;
import javax.jdo.Query;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class JsonbContainsMethodTest extends AbstractTest {

    @Test
    void shouldMatchWithStringParameter() {
        final var person = new Person();
        person.setProperties(/* language=JSON */ """
                [
                  {
                    "foo": "bar",
                    "baz": 111
                  }
                ]
                """);
        pm.makePersistent(person);

        final Query<Person> query = pm.newQuery(Person.class);
        query.setFilter("properties.jsonbContains(:foo)");
        query.setParameters("[{\"baz\":111}]");

        final Person queryResult = query.executeUnique();
        assertThat(queryResult).isNotNull();
    }

    @Test
    void shouldMatchWithStringLiteral() {
        final var person = new Person();
        person.setProperties(/* language=JSON */ """
                [
                  {
                    "foo": "bar",
                    "baz": 111
                  }
                ]
                """);
        pm.makePersistent(person);

        final Query<Person> query = pm.newQuery(Person.class);
        query.setFilter("properties.jsonbContains('[{\"baz\":111}]')");

        final Person queryResult = query.executeUnique();
        assertThat(queryResult).isNotNull();
    }

    @Test
    void shouldThrowForNonJsonStringArgument() {
        final var person = new Person();
        person.setProperties(/* language=JSON */ """
                [
                  {
                    "foo": "bar",
                    "baz": 111
                  }
                ]
                """);
        pm.makePersistent(person);

        final Query<Person> query = pm.newQuery(Person.class);
        query.setFilter("properties.jsonbContains('not-json')");
        query.setParameters(123);

        assertThatExceptionOfType(JDOException.class)
                .isThrownBy(query::executeUnique)
                .havingCause()
                .isInstanceOf(PSQLException.class)
                .withMessage("""
                        ERROR: invalid input syntax for type json
                          Detail: Token "not" is invalid.
                          Position: 178
                          Where: JSON data, line 1: not...""");
    }

    @Test
    void shouldThrowForNonStringArgument() {
        final var person = new Person();
        person.setProperties(/* language=JSON */ """
                [
                  {
                    "foo": "bar",
                    "baz": 111
                  }
                ]
                """);
        pm.makePersistent(person);

        final Query<Person> query = pm.newQuery(Person.class);
        query.setFilter("properties.jsonbContains(:foo)");
        query.setParameters(123);

        assertThatExceptionOfType(JDOException.class)
                .isThrownBy(query::executeUnique)
                .withMessage("""
                        Cannot invoke jsonbContains with argument of type \
                        org.datanucleus.store.rdbms.sql.expression.IntegerLiteral""");
    }

}
