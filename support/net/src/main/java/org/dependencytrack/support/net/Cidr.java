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
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/// @since 5.2.0
record Cidr(byte[] network, int prefixLength) {

    private static final Pattern IPV4_PATTERN = Pattern.compile("(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}");
    private static final Pattern PREFIX_LENGTH_PATTERN = Pattern.compile("0|[1-9][0-9]{0,2}");

    static Cidr parse(String value) {
        final int slashIndex = value.indexOf('/');
        final String address = slashIndex < 0 ? value : value.substring(0, slashIndex);

        if (!address.contains(":") && !IPV4_PATTERN.matcher(address).matches()) {
            throw new IllegalArgumentException("Invalid entry: %s".formatted(value));
        }

        final byte[] network;
        try {
            network = InetAddress.ofLiteral(address).getAddress();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid entry: %s".formatted(value), e);
        }

        final int prefixLength;
        if (slashIndex < 0) {
            prefixLength = network.length * 8;
        } else if (PREFIX_LENGTH_PATTERN
                .matcher(value.substring(slashIndex + 1))
                .matches()) {
            prefixLength = Integer.parseInt(value.substring(slashIndex + 1));
        } else {
            throw new IllegalArgumentException("Invalid prefix length in %s".formatted(value));
        }
        if (prefixLength > network.length * 8) {
            throw new IllegalArgumentException("Invalid prefix length in %s".formatted(value));
        }

        final byte[] maskedNetwork = masked(network, prefixLength);
        if (!Arrays.equals(network, maskedNetwork)) {
            throw new IllegalArgumentException("%s has host bits set, the network address is %s/%d"
                    .formatted(value, toHostAddress(maskedNetwork), prefixLength));
        }

        return new Cidr(network, prefixLength);
    }

    static List<Cidr> parseAll(String... values) {
        return Arrays.stream(values).map(Cidr::parse).toList();
    }

    static boolean anyContains(List<Cidr> cidrs, byte[] address) {
        return cidrs.stream().anyMatch(cidr -> cidr.contains(address));
    }

    static int longestMatchingPrefixLength(List<Cidr> cidrs, byte[] address) {
        return cidrs.stream()
                .filter(cidr -> cidr.contains(address))
                .mapToInt(Cidr::prefixLength)
                .max()
                .orElse(-1);
    }

    private static byte[] masked(byte[] address, int prefixLength) {
        final byte[] masked = address.clone();
        for (int i = 0; i < masked.length; i++) {
            final int bitsToKeep = Math.clamp(prefixLength - i * 8L, 0, 8);
            masked[i] &= (byte) (0xFF << (8 - bitsToKeep));
        }

        return masked;
    }

    private static String toHostAddress(byte[] address) {
        try {
            return InetAddress.getByAddress(address).getHostAddress();
        } catch (UnknownHostException e) {
            throw new IllegalStateException("A %d-byte address was rejected".formatted(address.length), e);
        }
    }

    private boolean contains(byte[] address) {
        return address.length == network.length && Arrays.equals(masked(address, prefixLength), network);
    }
}
