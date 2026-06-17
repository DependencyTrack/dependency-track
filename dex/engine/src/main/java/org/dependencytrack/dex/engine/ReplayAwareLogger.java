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
package org.dependencytrack.dex.engine;

import org.slf4j.Logger;
import org.slf4j.Marker;

/**
 * A {@link Logger} that omits log messages during workflow replay.
 */
final class ReplayAwareLogger implements Logger {

    private final WorkflowContextImpl<?, ?> workflowContext;
    private final Logger delegate;

    ReplayAwareLogger(
            final WorkflowContextImpl<?, ?> workflowContext,
            final Logger delegate) {
        this.workflowContext = workflowContext;
        this.delegate = delegate;
    }

    private void unlessReplaying(final Runnable runnable) {
        if (!workflowContext.isReplaying()) {
            runnable.run();
        }
    }

    @Override
    public String getName() {
        return delegate.getName();
    }

    @Override
    public boolean isTraceEnabled() {
        return delegate.isTraceEnabled();
    }

    @Override
    public void trace(final String s) {
        unlessReplaying(() -> delegate.trace(s));
    }

    @Override
    public void trace(final String s, final Object o) {
        unlessReplaying(() -> delegate.trace(s, o));
    }

    @Override
    public void trace(final String s, final Object o, final Object o1) {
        unlessReplaying(() -> delegate.trace(s, o, o1));
    }

    @Override
    public void trace(final String s, final Object... objects) {
        unlessReplaying(() -> delegate.trace(s, objects));
    }

    @Override
    public void trace(final String s, final Throwable throwable) {
        unlessReplaying(() -> delegate.trace(s, throwable));
    }

    @Override
    public boolean isTraceEnabled(final Marker marker) {
        return delegate.isTraceEnabled(marker);
    }

    @Override
    public void trace(final Marker marker, final String s) {
        unlessReplaying(() -> delegate.trace(marker, s));
    }

    @Override
    public void trace(final Marker marker, final String s, final Object o) {
        unlessReplaying(() -> delegate.trace(marker, s, o));
    }

    @Override
    public void trace(final Marker marker, final String s, final Object o, final Object o1) {
        unlessReplaying(() -> delegate.trace(marker, s, o, o1));
    }

    @Override
    public void trace(final Marker marker, final String s, final Object... objects) {
        unlessReplaying(() -> delegate.trace(marker, s, objects));
    }

    @Override
    public void trace(final Marker marker, final String s, final Throwable throwable) {
        unlessReplaying(() -> delegate.trace(marker, s, throwable));
    }

    @Override
    public boolean isDebugEnabled() {
        return delegate.isDebugEnabled();
    }

    @Override
    public void debug(final String s) {
        unlessReplaying(() -> delegate.debug(s));
    }

    @Override
    public void debug(final String s, final Object o) {
        unlessReplaying(() -> delegate.debug(s, o));
    }

    @Override
    public void debug(final String s, final Object o, final Object o1) {
        unlessReplaying(() -> delegate.debug(s, o, o1));
    }

    @Override
    public void debug(final String s, final Object... objects) {
        unlessReplaying(() -> delegate.debug(s, objects));
    }

    @Override
    public void debug(final String s, final Throwable throwable) {
        unlessReplaying(() -> delegate.debug(s, throwable));
    }

    @Override
    public boolean isDebugEnabled(final Marker marker) {
        return delegate.isDebugEnabled(marker);
    }

    @Override
    public void debug(final Marker marker, final String s) {
        unlessReplaying(() -> delegate.debug(marker, s));
    }

    @Override
    public void debug(final Marker marker, final String s, final Object o) {
        unlessReplaying(() -> delegate.debug(marker, s, o));
    }

    @Override
    public void debug(final Marker marker, final String s, final Object o, final Object o1) {
        unlessReplaying(() -> delegate.debug(marker, s, o, o1));
    }

    @Override
    public void debug(final Marker marker, final String s, final Object... objects) {
        unlessReplaying(() -> delegate.debug(marker, s, objects));
    }

    @Override
    public void debug(final Marker marker, final String s, final Throwable throwable) {
        unlessReplaying(() -> delegate.debug(marker, s, throwable));
    }

    @Override
    public boolean isInfoEnabled() {
        return delegate.isInfoEnabled();
    }

    @Override
    public void info(final String s) {
        unlessReplaying(() -> delegate.info(s));
    }

    @Override
    public void info(final String s, final Object o) {
        unlessReplaying(() -> delegate.info(s, o));
    }

    @Override
    public void info(final String s, final Object o, final Object o1) {
        unlessReplaying(() -> delegate.info(s, o, o1));
    }

    @Override
    public void info(final String s, final Object... objects) {
        unlessReplaying(() -> delegate.info(s, objects));
    }

    @Override
    public void info(final String s, final Throwable throwable) {
        unlessReplaying(() -> delegate.info(s, throwable));
    }

    @Override
    public boolean isInfoEnabled(final Marker marker) {
        return delegate.isInfoEnabled(marker);
    }

    @Override
    public void info(final Marker marker, final String s) {
        unlessReplaying(() -> delegate.info(marker, s));
    }

    @Override
    public void info(final Marker marker, final String s, final Object o) {
        unlessReplaying(() -> delegate.info(marker, s, o));
    }

    @Override
    public void info(final Marker marker, final String s, final Object o, final Object o1) {
        unlessReplaying(() -> delegate.info(marker, s, o, o1));
    }

    @Override
    public void info(final Marker marker, final String s, final Object... objects) {
        unlessReplaying(() -> delegate.info(marker, s, objects));
    }

    @Override
    public void info(final Marker marker, final String s, final Throwable throwable) {
        unlessReplaying(() -> delegate.info(marker, s, throwable));
    }

    @Override
    public boolean isWarnEnabled() {
        return delegate.isWarnEnabled();
    }

    @Override
    public void warn(final String s) {
        unlessReplaying(() -> delegate.warn(s));
    }

    @Override
    public void warn(final String s, final Object o) {
        unlessReplaying(() -> delegate.warn(s, o));
    }

    @Override
    public void warn(final String s, final Object... objects) {
        unlessReplaying(() -> delegate.warn(s, objects));
    }

    @Override
    public void warn(final String s, final Object o, final Object o1) {
        unlessReplaying(() -> delegate.warn(s, o, o1));
    }

    @Override
    public void warn(final String s, final Throwable throwable) {
        unlessReplaying(() -> delegate.warn(s, throwable));
    }

    @Override
    public boolean isWarnEnabled(final Marker marker) {
        return delegate.isWarnEnabled(marker);
    }

    @Override
    public void warn(final Marker marker, final String s) {
        unlessReplaying(() -> delegate.warn(marker, s));
    }

    @Override
    public void warn(final Marker marker, final String s, final Object o) {
        unlessReplaying(() -> delegate.warn(marker, s, o));
    }

    @Override
    public void warn(final Marker marker, final String s, final Object o, final Object o1) {
        unlessReplaying(() -> delegate.warn(marker, s, o, o1));
    }

    @Override
    public void warn(final Marker marker, final String s, final Object... objects) {
        unlessReplaying(() -> delegate.warn(marker, s, objects));
    }

    @Override
    public void warn(final Marker marker, final String s, final Throwable throwable) {
        unlessReplaying(() -> delegate.warn(marker, s, throwable));
    }

    @Override
    public boolean isErrorEnabled() {
        return delegate.isErrorEnabled();
    }

    @Override
    public void error(final String s) {
        unlessReplaying(() -> delegate.error(s));
    }

    @Override
    public void error(final String s, final Object o) {
        unlessReplaying(() -> delegate.error(s, o));
    }

    @Override
    public void error(final String s, final Object o, final Object o1) {
        unlessReplaying(() -> delegate.error(s, o, o1));
    }

    @Override
    public void error(final String s, final Object... objects) {
        unlessReplaying(() -> delegate.error(s, objects));
    }

    @Override
    public void error(final String s, final Throwable throwable) {
        unlessReplaying(() -> delegate.error(s, throwable));
    }

    @Override
    public boolean isErrorEnabled(final Marker marker) {
        return delegate.isErrorEnabled(marker);
    }

    @Override
    public void error(final Marker marker, final String s) {
        unlessReplaying(() -> delegate.error(marker, s));
    }

    @Override
    public void error(final Marker marker, final String s, final Object o) {
        unlessReplaying(() -> delegate.error(marker, s, o));
    }

    @Override
    public void error(final Marker marker, final String s, final Object o, final Object o1) {
        unlessReplaying(() -> delegate.error(marker, s, o, o1));
    }

    @Override
    public void error(final Marker marker, final String s, final Object... objects) {
        unlessReplaying(() -> delegate.error(marker, s, objects));
    }

    @Override
    public void error(final Marker marker, final String s, final Throwable throwable) {
        unlessReplaying(() -> delegate.error(marker, s, throwable));
    }

}
