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

import javax.net.ssl.SSLHandshakeException;
import java.io.EOFException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.ProtocolException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.http.HttpTimeoutException;
import java.nio.channels.ClosedChannelException;

import static org.assertj.core.api.Assertions.assertThat;

class TransientNetworkErrorsTest {

    @Test
    void shouldClassifyConnectivityAndTimeoutFailuresAsTransient() {
        assertThat(TransientNetworkErrors.isTransient(new ConnectException("refused"))).isTrue();
        assertThat(TransientNetworkErrors.isTransient(new SocketException("reset"))).isTrue();
        assertThat(TransientNetworkErrors.isTransient(new SocketTimeoutException("read timed out"))).isTrue();
        assertThat(TransientNetworkErrors.isTransient(new HttpTimeoutException("timed out"))).isTrue();
        assertThat(TransientNetworkErrors.isTransient(new EOFException())).isTrue();
        assertThat(TransientNetworkErrors.isTransient(new ClosedChannelException())).isTrue();
        assertThat(TransientNetworkErrors.isTransient(new UnknownHostException("resolver blip"))).isTrue();
    }

    @Test
    void shouldClassifyPermanentFailuresAsNotTransient() {
        assertThat(TransientNetworkErrors.isTransient(new SSLHandshakeException("bad cert"))).isFalse();
        assertThat(TransientNetworkErrors.isTransient(new ProtocolException("invalid response"))).isFalse();
        assertThat(TransientNetworkErrors.isTransient(new InterruptedIOException("interrupted"))).isFalse();
        assertThat(TransientNetworkErrors.isTransient(new IOException("malformed response"))).isFalse();
    }

    @Test
    void shouldWalkCauseChainForWrappedTransportFailure() {
        final var wrapped = new IOException(
                "HTTP/1.1 header parser received no bytes",
                new SocketException("Connection reset"));
        assertThat(TransientNetworkErrors.isTransient(wrapped)).isTrue();
    }

}
