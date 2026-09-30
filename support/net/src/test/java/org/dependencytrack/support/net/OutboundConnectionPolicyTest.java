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
package org.dependencytrack.support.net;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class OutboundConnectionPolicyTest {

    @ParameterizedTest(name = "[{index}] entries={0} host={1} address={2} allowed={3}")
    @CsvSource(delimiter = '|', textBlock = """
            external,private     | example.com          | 93.184.215.14         | true
            external,private     | example.com          | 2606:2800:21f:cb07::1 | true
            external,private     | internal             | 10.1.2.3              | true
            external,private     | internal             | 172.16.0.1            | true
            external,private     | internal             | 192.168.1.1           | true
            external,private     | internal             | 100.64.0.1            | true
            external,private     | internal             | fd12::1               | true
            external,private     | localhost            | 127.0.0.1             | false
            external,private     | localhost            | 127.1.2.3             | false
            external,private     | localhost            | ::1                   | false
            external,private     | metadata             | fd00:ec2::254         | false
            external,private     | metadata             | fd20:ce::254          | false
            external,private     | metadata             | 100.100.100.200       | false
            external,private     | metadata             | 168.63.129.16         | false
            external,private     | link-local           | 169.254.1.1           | false
            external,private     | link-local           | fe80::1               | false
            external,private     | unspecified          | 0.0.0.0               | false
            external,private     | unspecified          | ::                    | false
            external,private     | nat64                | 64:ff9b::a9fe:a9fe    | false
            external,private     | nat64                | 64:ff9b::5db8:d70e    | true
            external             | internal             | 10.1.2.3              | false
            external             | internal             | fd12::1               | false
            external             | example.com          | 93.184.215.14         | true
            private              | example.com          | 93.184.215.14         | false
            loopback             | localhost            | 127.0.0.1             | true
            loopback             | localhost            | ::1                   | true
            loopback             | internal             | 10.1.2.3              | false
            10.1.0.0/16          | internal             | 10.1.2.3              | true
            10.1.0.0/16          | internal             | 10.2.0.1              | false
            fd00:ec2::/32        | metadata             | fd00:ec2::254         | true
            169.254.169.254      | metadata             | 169.254.169.254       | true
            169.254.169.254      | metadata             | 169.254.169.253       | false
            169.254.0.0/16       | link-local           | 169.254.1.1           | true
            169.254.0.0/16       | metadata             | 169.254.169.254       | false
            fd00::/8             | internal             | fd12::1               | true
            fd00::/8             | metadata             | fd00:ec2::254         | false
            0.0.0.0/0            | example.com          | 93.184.215.14         | true
            0.0.0.0/0            | metadata             | 169.254.169.254       | false
            internal.example.com | internal.example.com | 127.0.0.1             | true
            internal.example.com | INTERNAL.example.com | 127.0.0.1             | true
            internal.example.com | other.example.com    | 127.0.0.1             | false
            internal.example.com | internal.example.com | 169.254.169.254       | false
            [::1]                | localhost            | ::1                   | true
            *                    | metadata             | 169.254.169.254       | true
            """)
    void isAllowedShouldEvaluateAddress(String entries, String host, String address, boolean expectedAllowed) {
        final var policy = OutboundConnectionPolicy.of(Arrays.asList(entries.split(",")));

        assertThat(policy.isAllowed(host, InetAddress.ofLiteral(address))).isEqualTo(expectedAllowed);
    }

    @ParameterizedTest(name = "[{index}] address={0} allowed={1}")
    @CsvSource(delimiter = '|', textBlock = """
            127.0.0.1       | false
            169.254.169.254 | false
            10.1.2.3        | true
            93.184.215.14   | true
            """)
    void isAllowedShouldEvaluateIpv4MappedAddress(String ipv4Address, boolean expectedAllowed)
            throws UnknownHostException {
        final var policy = OutboundConnectionPolicy.of(List.of("external", "private"));

        // Assemble an IPv4-mapped IPv6 address in the form of `::ffff:a.b.c.d`.
        final byte[] mappedAddress = ByteBuffer.allocate(16)
                .position(10)
                .putShort((short) 0xffff)
                .put(InetAddress.ofLiteral(ipv4Address).getAddress())
                .array();

        assertThat(policy.isAllowed("example.com", Inet6Address.getByAddress(null, mappedAddress, -1)))
                .isEqualTo(expectedAllowed);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "10.0.0.0/33",
                "fd00::/129",
                "10.0.0.0/abc",
                "not-an-ip/8",
                "*.example.com",
                "example.com:8080",
                "exa_mple.com",
                "010.0.0.1",
                "10.1",
                "2130706433",
                "123",
                "10.0.0.0/08",
                "10.0.0.0/+8",
                "10.0.0.0/\u0668",
                "10.0.0.1/8",
                "fd00::1/8"
            })
    void ofShouldRejectInvalidEntry(String entry) {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> OutboundConnectionPolicy.of(List.of(entry)))
                .withMessageContaining(entry);
    }

    @ParameterizedTest
    @MethodSource("entriesWithoutAnyEntry")
    void ofShouldRejectEntriesWithoutAnyEntry(List<String> entries) {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> OutboundConnectionPolicy.of(entries))
                .withMessage("At least one entry is required");
    }

    private static Stream<List<String>> entriesWithoutAnyEntry() {
        return Stream.of(List.of(), List.of(" "), List.of("", "\t", "  "));
    }

    @Test
    void ofShouldRejectWildcardWithOtherEntries() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> OutboundConnectionPolicy.of(List.of("*", "loopback")))
                .withMessage("* must be the only entry");
    }

    @Test
    void requireAllowedShouldReturnAddressesOfAllowedHost() throws Exception {
        final var policy = OutboundConnectionPolicy.of(List.of("loopback"));

        assertThat(policy.requireAllowed("127.0.0.1")).containsExactly(InetAddress.ofLiteral("127.0.0.1"));
    }

    @Test
    void requireAllowedShouldRejectHostWithAnyDeniedAddress() {
        final var policy = OutboundConnectionPolicy.of(List.of("private"));

        // NB: mixed.invalid is resolved via src/test/resources/hosts,
        // configured via jdk.net.hosts.file system property in surefire.
        // The hostname resolves to one private (i.e. allowed) and one loopback address.
        assertThatExceptionOfType(OutboundConnectionDeniedException.class)
                .isThrownBy(() -> policy.requireAllowed("mixed.invalid"))
                .withMessageContaining("127.0.0.1");
    }
}
