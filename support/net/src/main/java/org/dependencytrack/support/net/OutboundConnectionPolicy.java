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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/// @since 5.2.0
public final class OutboundConnectionPolicy {

    // Prefix of IPv4-mapped IPv6 addresses, i.e. `::ffff:`.
    // https://www.rfc-editor.org/info/rfc4291/#section-2.5.5.2
    private static final byte[] IPV4_MAPPED_PREFIX = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xff, (byte) 0xff};

    // IPv6 prefix for NAT64 translation.
    // https://www.rfc-editor.org/info/rfc6052/#section-2.1
    private static final byte[] NAT64_PREFIX = {0, 0x64, (byte) 0xff, (byte) 0x9b, 0, 0, 0, 0, 0, 0, 0, 0};

    // Valid hostname pattern per https://www.rfc-editor.org/info/rfc1123/#section-2.1.
    private static final Pattern HOSTNAME_PATTERN =
            Pattern.compile("[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*");

    private final boolean allowAll;
    private final boolean externalAllowed;
    private final boolean privateAllowed;
    private final boolean loopbackAllowed;
    private final List<Cidr> allowedRanges;
    private final Set<String> allowedHosts;

    private OutboundConnectionPolicy(
            boolean allowAll,
            boolean externalAllowed,
            boolean privateAllowed,
            boolean loopbackAllowed,
            List<Cidr> allowedRanges,
            Set<String> allowedHosts) {
        this.allowAll = allowAll;
        this.externalAllowed = externalAllowed;
        this.privateAllowed = privateAllowed;
        this.loopbackAllowed = loopbackAllowed;
        this.allowedRanges = allowedRanges;
        this.allowedHosts = allowedHosts;
    }

    public static OutboundConnectionPolicy of(Collection<String> entries) {
        boolean allowAll = false;
        boolean externalAllowed = false;
        boolean privateAllowed = false;
        boolean loopbackAllowed = false;
        final var allowedRanges = new ArrayList<Cidr>();
        final var allowedHosts = new HashSet<String>();
        int entryCount = 0;

        for (final String rawEntry : entries) {
            final String entry = rawEntry.trim().toLowerCase(Locale.ROOT);
            if (entry.isEmpty()) {
                continue;
            }

            entryCount++;
            switch (entry) {
                case "*" -> allowAll = true;
                case "external" -> externalAllowed = true;
                case "private" -> privateAllowed = true;
                case "loopback" -> loopbackAllowed = true;
                default -> {
                    if (entry.contains("/") || isIpLiteral(entry)) {
                        allowedRanges.add(Cidr.parse(entry));
                    } else if (HOSTNAME_PATTERN.matcher(entry).matches()) {
                        allowedHosts.add(entry);
                    } else {
                        throw new IllegalArgumentException("Invalid entry: %s".formatted(rawEntry));
                    }
                }
            }
        }

        if (entryCount == 0) {
            throw new IllegalArgumentException("At least one entry is required");
        }
        if (allowAll && entryCount > 1) {
            throw new IllegalArgumentException("* must be the only entry");
        }

        return new OutboundConnectionPolicy(
                allowAll,
                externalAllowed,
                privateAllowed,
                loopbackAllowed,
                List.copyOf(allowedRanges),
                Set.copyOf(allowedHosts));
    }

    /// Resolves the host and verifies **every address** it resolves to.
    /// Hosts that have both allowed and denied addresses are rejected.
    ///
    /// @return The resolved and verified addresses.
    /// @throws UnknownHostException When resolving addresses for the host failed.
    /// @throws OutboundConnectionDeniedException When at least one resolved address is denied.
    public List<InetAddress> requireAllowed(String host)
            throws UnknownHostException, OutboundConnectionDeniedException {
        final var addresses = List.of(InetAddress.getAllByName(host));
        for (final InetAddress address : addresses) {
            if (!isAllowed(host, address)) {
                throw new OutboundConnectionDeniedException(
                        "Connections to %s (%s) are not allowed".formatted(host, address.getHostAddress()));
            }
        }

        return addresses;
    }

    boolean isAllowed(String host, InetAddress address) {
        final byte[] effectiveAddress = maybeUnwrapIpV4(address.getAddress());
        if (allowAll) {
            return true;
        }

        final int deniedPrefixLength = Cidr.longestMatchingPrefixLength(AddressRanges.DENIED, effectiveAddress);
        final int allowedPrefixLength = Cidr.longestMatchingPrefixLength(allowedRanges, effectiveAddress);
        if (allowedPrefixLength >= 0 && allowedPrefixLength >= deniedPrefixLength) {
            return true;
        }

        final boolean hostAllowed = allowedHosts.contains(host.toLowerCase(Locale.ROOT));
        if (Cidr.anyContains(AddressRanges.LOOPBACK, effectiveAddress)) {
            return loopbackAllowed || hostAllowed;
        }
        if (deniedPrefixLength >= 0) {
            return false;
        }
        if (hostAllowed) {
            return true;
        }
        if (Cidr.anyContains(AddressRanges.PRIVATE, effectiveAddress)) {
            return privateAllowed;
        }

        return externalAllowed;
    }

    /// Unwraps IPv4-mapped and NAT64 addresses.
    ///
    /// DNS answers can contain IPv4-mapped addresses, and IPv6-only networks
    /// with DNS64 use the NAT64 prefix for every IPv4 destination, as explained
    /// [here](https://docs.aws.amazon.com/vpc/latest/userguide/nat-gateway-nat64-dns64.html).
    private static byte[] maybeUnwrapIpV4(byte[] address) {
        if (address.length != 16
                || !(Arrays.equals(address, 0, 12, IPV4_MAPPED_PREFIX, 0, 12)
                        || Arrays.equals(address, 0, 12, NAT64_PREFIX, 0, 12))) {
            return address;
        }

        return Arrays.copyOfRange(address, 12, 16);
    }

    private static boolean isIpLiteral(String value) {
        try {
            var _ = InetAddress.ofLiteral(value);
            return true;
        } catch (IllegalArgumentException _) {
            return false;
        }
    }
}
