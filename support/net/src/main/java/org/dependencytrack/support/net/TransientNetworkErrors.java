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

import java.io.EOFException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.http.HttpTimeoutException;
import java.nio.channels.ClosedChannelException;

/// @since 5.1.0
public final class TransientNetworkErrors {

    private TransientNetworkErrors() {
    }

    /// @param throwable The [Throwable] to inspect.
    /// @return `true` when `throwable` is, or was caused by, a transient network error.
    public static boolean isTransient(Throwable throwable) {
        for (Throwable cause = throwable; cause != null; cause = cause.getCause()) {
            if (cause instanceof ClosedChannelException
                    || cause instanceof EOFException
                    || cause instanceof HttpTimeoutException
                    || cause instanceof SocketException
                    || cause instanceof SocketTimeoutException
                    || cause instanceof UnknownHostException) {
                return true;
            }
        }

        return false;
    }

}
