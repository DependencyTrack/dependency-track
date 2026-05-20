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
package org.dependencytrack.capabilities;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SystemCapabilitiesAggregatorTest {

    @Test
    void shouldFailFastOnDuplicateNamespace() {
        final var providerA = new DummyProvider("foo", Map.of("a", true));
        final var providerB = new DummyProvider("foo", Map.of("b", false));

        assertThatThrownBy(() -> new SystemCapabilitiesAggregator(List.of(providerA, providerB), null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Duplicate capability namespace 'foo'");
    }

    @Test
    void shouldOmitNamespaceWhenProviderThrows() {
        final var throwing = new ThrowingProvider("broken");
        final var working = new DummyProvider("ok", Map.of("flag", true));

        final var aggregator = new SystemCapabilitiesAggregator(List.of(throwing, working), null);

        assertThat(aggregator.collect()).containsOnlyKeys("ok");
    }

    @Test
    void shouldReturnEmptyResponseWhenNoProviders() {
        final var aggregator = new SystemCapabilitiesAggregator(List.of(), null);

        assertThat(aggregator.collect()).isEmpty();
    }

    @Test
    void shouldOrderNamespacesAndFlagsAlphabetically() {
        final var providers = List.<CapabilityProvider>of(
                new DummyProvider("zebra", Map.of("zeta", 1, "alpha", 2)),
                new DummyProvider("alpha", Map.of("z", "x", "a", "y")));

        final var aggregator = new SystemCapabilitiesAggregator(providers, null);

        assertThat(aggregator.collect()).containsExactly(
                Map.entry("alpha", Map.of("a", "y", "z", "x")),
                Map.entry("zebra", Map.of("alpha", 2, "zeta", 1)));
        assertThat(aggregator.collect().get("alpha").keySet()).containsExactly("a", "z");
        assertThat(aggregator.collect().get("zebra").keySet()).containsExactly("alpha", "zeta");
    }

    @Test
    void shouldOmitEmptyNamespaces() {
        final var providers = List.<CapabilityProvider>of(
                new DummyProvider("empty", Map.of()),
                new DummyProvider("non_empty", Map.of("flag", true)));

        final var aggregator = new SystemCapabilitiesAggregator(providers, null);

        assertThat(aggregator.collect()).containsOnlyKeys("non_empty");
    }

    @Test
    void shouldOmitNamespaceWhenValueIsUnsupportedType() {
        final var providers = List.<CapabilityProvider>of(
                new DummyProvider("namespace", Map.of("when", Instant.EPOCH)));

        final var aggregator = new SystemCapabilitiesAggregator(providers, null);

        assertThat(aggregator.collect()).isEmpty();
    }

    @Test
    void shouldOmitNamespaceWhenNestedValueIsUnsupportedType() {
        final var providers = List.<CapabilityProvider>of(
                new DummyProvider("namespace", Map.of(
                        "nested", Map.of("when", Instant.EPOCH))));

        final var aggregator = new SystemCapabilitiesAggregator(providers, null);

        assertThat(aggregator.collect()).isEmpty();
    }

    @Test
    void shouldOmitNamespaceWhenTopLevelKeyIsNonString() {
        @SuppressWarnings({"unchecked", "rawtypes"}) final var providers =
                List.<CapabilityProvider>of(
                        new DummyProvider("ns", (Map) Map.of(42, true)));

        final var aggregator = new SystemCapabilitiesAggregator(providers, null);

        assertThat(aggregator.collect()).isEmpty();
    }

    @Test
    void shouldOmitNamespaceWhenNestedKeyIsNonString() {
        final var providers = List.<CapabilityProvider>of(
                new DummyProvider("ns", Map.of("nested", Map.of(42, true))));

        final var aggregator = new SystemCapabilitiesAggregator(providers, null);

        assertThat(aggregator.collect()).isEmpty();
    }

    @Test
    void shouldAcceptNestedPrimitivesListsAndMaps() {
        final var providers = List.<CapabilityProvider>of(
                new DummyProvider("namespace", Map.of(
                        "flag", true,
                        "count", 42,
                        "mode", "strict",
                        "tags", List.of("a", "b"),
                        "nested", Map.of("flag", false))));

        final var aggregator = new SystemCapabilitiesAggregator(providers, null);

        assertThat(aggregator.collect()).containsOnlyKeys("namespace");
    }

    private record DummyProvider(String namespace, Map<String, Object> capabilities) implements CapabilityProvider {
    }

    private record ThrowingProvider(String namespace) implements CapabilityProvider {

        @Override
        public @NonNull Map<String, Object> capabilities() {
            throw new RuntimeException("boom");
        }

    }

}
