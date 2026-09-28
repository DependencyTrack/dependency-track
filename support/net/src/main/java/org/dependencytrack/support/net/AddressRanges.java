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

import java.util.List;
import java.util.stream.Stream;

/// @since 5.2.0
final class AddressRanges {

    static final List<Cidr> LOOPBACK = Cidr.parseAll("127.0.0.0/8", "::1/128");

    static final List<Cidr> PRIVATE =
            Cidr.parseAll("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7");

    private static final List<Cidr> CLOUD_PROVIDER = Cidr.parseAll(
            // AWS, Azure, and GCP instance metadata.
            // https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
            // https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
            // https://docs.cloud.google.com/compute/docs/metadata/querying-metadata
            "169.254.169.254/32",
            // Alibaba Cloud instance metadata.
            // https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata
            "100.100.100.200/32",
            // AWS instance metadata, DNS resolver, and time sync.
            // https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
            // https://docs.aws.amazon.com/vpc/latest/userguide/AmazonDNS-concepts.html
            // https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configure-ec2-ntp.html
            "fd00:ec2::/32",
            // Azure WireServer, used by the VM agent, DNS, DHCP, and load balancer health probes.
            // https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16
            "168.63.129.16/32",
            // GCP instance metadata on IPv6-only instances.
            // https://docs.cloud.google.com/compute/docs/metadata/querying-metadata
            "fd20:ce::254/128");

    // Special-purpose blocks that reach the local host or services on it.
    private static final List<Cidr> SPECIAL_PURPOSE = Cidr.parseAll(
            // "This network"
            "0.0.0.0/8",
            // Link Local
            "169.254.0.0/16",
            // Unspecified Address
            "::/128",
            // Link-Local Unicast
            "fe80::/10");

    static final List<Cidr> DENIED =
            Stream.concat(CLOUD_PROVIDER.stream(), SPECIAL_PURPOSE.stream()).toList();

    private AddressRanges() {}
}
