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
package org.dependencytrack.pkgmetadata.resolution.cache;

import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow.Subscription;

/**
 * @since 5.0.0
 */
final class LimitedBodySubscriber implements HttpResponse.BodySubscriber<byte[]> {

    private final long maxBytes;
    private final List<byte[]> chunks = new ArrayList<>();
    private final CompletableFuture<byte[]> result = new CompletableFuture<>();
    private long received;
    private @Nullable Subscription subscription;

    public LimitedBodySubscriber(long maxBytes) {
        this.maxBytes = maxBytes;
    }

    @Override
    public CompletionStage<byte[]> getBody() {
        return result;
    }

    @Override
    public void onSubscribe(Subscription subscription) {
        this.subscription = subscription;
        subscription.request(Long.MAX_VALUE);
    }

    @Override
    public void onNext(List<ByteBuffer> items) {
        if (result.isDone()) {
            return;
        }

        for (final ByteBuffer item : items) {
            final int remaining = item.remaining();
            received += remaining;
            if (received > maxBytes) {
                if (subscription != null) {
                    subscription.cancel();
                }
                chunks.clear();
                result.completeExceptionally(
                        new IOException("Response body exceeds %d bytes".formatted(maxBytes)));
                return;
            }

            // The HTTP client may pool and reuse the underlying buffers
            // once onNext returns, so copy the bytes out instead of retaining
            // the ByteBuffer reference.
            final byte[] chunk = new byte[remaining];
            item.get(chunk);
            chunks.add(chunk);
        }
    }

    @Override
    public void onError(Throwable throwable) {
        result.completeExceptionally(throwable);
    }

    @Override
    public void onComplete() {
        if (result.isDone()) {
            return;
        }

        final byte[] out = new byte[(int) received];
        int pos = 0;
        for (final byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, out, pos, chunk.length);
            pos += chunk.length;
        }
        result.complete(out);
    }
}
