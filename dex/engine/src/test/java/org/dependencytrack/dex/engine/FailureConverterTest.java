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

import org.dependencytrack.dex.api.failure.ApplicationFailureException;
import org.dependencytrack.dex.api.failure.FailureException;
import org.dependencytrack.dex.api.failure.InternalFailureException;
import org.dependencytrack.dex.proto.failure.v1.ApplicationFailureDetails;
import org.dependencytrack.dex.proto.failure.v1.Failure;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class FailureConverterTest {

    @Test
    void shouldSerializeStackTrace() {
        var exception = new ApplicationFailureException("test", null);
        exception.setStackTrace(new StackTraceElement[]{
                new StackTraceElement("com.example.Foo", "doStuff", "Foo.java", 42),
                new StackTraceElement("com.example.Bar", "run", "Bar.java", 10),
        });

        final Failure failure = FailureConverter.toFailure(exception);

        assertThat(failure.getStackTrace())
                .isEqualTo("com.example.Foo.doStuff(Foo.java:42)\ncom.example.Bar.run(Bar.java:10)");
    }

    @Test
    void shouldSerializeStackTraceWithoutFileName() {
        var exception = new ApplicationFailureException("test", null);
        exception.setStackTrace(new StackTraceElement[]{
                new StackTraceElement("com.example.Foo", "doStuff", null, -1),
        });

        final Failure failure = FailureConverter.toFailure(exception);

        assertThat(failure.getStackTrace()).isEqualTo("com.example.Foo.doStuff");
    }

    @Test
    void shouldSerializeConstructorFrame() {
        var exception = new ApplicationFailureException("test", null);
        exception.setStackTrace(new StackTraceElement[]{
                new StackTraceElement("com.example.Foo", "<init>", "Foo.java", 15),
                new StackTraceElement("com.example.Bar", "create", "Bar.java", 30),
        });

        final Failure failure = FailureConverter.toFailure(exception);

        assertThat(failure.getStackTrace())
                .isEqualTo("com.example.Foo.<init>(Foo.java:15)\ncom.example.Bar.create(Bar.java:30)");
    }

    @Test
    void shouldSerializeStaticInitializerFrame() {
        var exception = new ApplicationFailureException("test", null);
        exception.setStackTrace(new StackTraceElement[]{
                new StackTraceElement("com.example.Foo", "<clinit>", "Foo.java", 5),
        });

        final Failure failure = FailureConverter.toFailure(exception);

        assertThat(failure.getStackTrace()).isEqualTo("com.example.Foo.<clinit>(Foo.java:5)");
    }

    @Test
    void shouldRoundTripConstructorFrame() {
        var exception = new ApplicationFailureException("constructor fail", null);
        exception.setStackTrace(new StackTraceElement[]{
                new StackTraceElement("com.example.Foo", "<init>", "Foo.java", 15),
                new StackTraceElement("com.example.Bar", "create", "Bar.java", 30),
        });

        final Failure failure = FailureConverter.toFailure(exception);
        final FailureException restored = FailureConverter.toException(failure);

        assertThat(restored.getStackTrace()).hasSize(2);
        assertThat(restored.getStackTrace()[0]).satisfies(e -> {
            assertThat(e.getClassName()).isEqualTo("com.example.Foo");
            assertThat(e.getMethodName()).isEqualTo("<init>");
            assertThat(e.getFileName()).isEqualTo("Foo.java");
            assertThat(e.getLineNumber()).isEqualTo(15);
        });
        assertThat(restored.getStackTrace()[1]).satisfies(e -> {
            assertThat(e.getClassName()).isEqualTo("com.example.Bar");
            assertThat(e.getMethodName()).isEqualTo("create");
            assertThat(e.getFileName()).isEqualTo("Bar.java");
            assertThat(e.getLineNumber()).isEqualTo(30);
        });
    }

    @Test
    void shouldRoundTripStaticInitializerFrame() {
        var exception = new ApplicationFailureException("clinit fail", null);
        exception.setStackTrace(new StackTraceElement[]{
                new StackTraceElement("com.example.Foo", "<clinit>", "Foo.java", 5),
        });

        final Failure failure = FailureConverter.toFailure(exception);
        final FailureException restored = FailureConverter.toException(failure);

        assertThat(restored.getStackTrace()).hasSize(1);
        assertThat(restored.getStackTrace()[0].getMethodName()).isEqualTo("<clinit>");
    }

    @Test
    void shouldRoundTripHiddenClassFrame() {
        var exception = new ApplicationFailureException("lambda fail", null);
        exception.setStackTrace(new StackTraceElement[]{
                new StackTraceElement(
                        "com.example.Foo$$Lambda/0x00007f8e8c0a1000", "run", null, -1),
        });

        final Failure failure = FailureConverter.toFailure(exception);
        final FailureException restored = FailureConverter.toException(failure);

        assertThat(restored.getStackTrace()).hasSize(1);
        assertThat(restored.getStackTrace()[0]).satisfies(e -> {
            assertThat(e.getClassName())
                    .isEqualTo("com.example.Foo$$Lambda/0x00007f8e8c0a1000");
            assertThat(e.getMethodName()).isEqualTo("run");
            assertThat(e.getFileName()).isNull();
        });
    }

    @Test
    void shouldRoundTripInnerClassFrame() {
        var exception = new ApplicationFailureException("inner class fail", null);
        exception.setStackTrace(new StackTraceElement[]{
                new StackTraceElement("com.example.Outer$Inner", "process", "Outer.java", 99),
        });

        final Failure failure = FailureConverter.toFailure(exception);
        final FailureException restored = FailureConverter.toException(failure);

        assertThat(restored.getStackTrace()).hasSize(1);
        assertThat(restored.getStackTrace()[0]).satisfies(e -> {
            assertThat(e.getClassName()).isEqualTo("com.example.Outer$Inner");
            assertThat(e.getMethodName()).isEqualTo("process");
            assertThat(e.getFileName()).isEqualTo("Outer.java");
            assertThat(e.getLineNumber()).isEqualTo(99);
        });
    }

    @Test
    void shouldRoundTripLambdaMethodFrame() {
        var exception = new ApplicationFailureException("lambda method fail", null);
        exception.setStackTrace(new StackTraceElement[]{
                new StackTraceElement("com.example.Foo", "lambda$process$0", "Foo.java", 42),
        });

        final Failure failure = FailureConverter.toFailure(exception);
        final FailureException restored = FailureConverter.toException(failure);

        assertThat(restored.getStackTrace()).hasSize(1);
        assertThat(restored.getStackTrace()[0]).satisfies(e -> {
            assertThat(e.getClassName()).isEqualTo("com.example.Foo");
            assertThat(e.getMethodName()).isEqualTo("lambda$process$0");
        });
    }

    @Test
    void shouldRoundTripFrameWithoutFileInfo() {
        var exception = new ApplicationFailureException("no file", null);
        exception.setStackTrace(new StackTraceElement[]{
                new StackTraceElement("com.example.Foo", "doStuff", null, -1),
        });

        final Failure failure = FailureConverter.toFailure(exception);
        final FailureException restored = FailureConverter.toException(failure);

        assertThat(restored.getStackTrace()).hasSize(1);
        assertThat(restored.getStackTrace()[0]).satisfies(e -> {
            assertThat(e.getClassName()).isEqualTo("com.example.Foo");
            assertThat(e.getMethodName()).isEqualTo("doStuff");
            assertThat(e.getFileName()).isNull();
            assertThat(e.getLineNumber()).isEqualTo(-1);
        });
    }

    @Test
    void shouldNotSerializeEmptyStackTrace() {
        var exception = new ApplicationFailureException("no trace", null);
        exception.setStackTrace(new StackTraceElement[0]);

        final Failure failure = FailureConverter.toFailure(exception);

        assertThat(failure.hasStackTrace()).isFalse();
    }

    @Test
    void shouldRejectMalformedStackTraceElement() {
        final Failure failure = Failure.newBuilder()
                .setMessage("test")
                .setStackTrace("!!not-a-valid-frame!!")
                .setApplicationFailureDetails(ApplicationFailureDetails.getDefaultInstance())
                .build();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> FailureConverter.toException(failure))
                .withMessageContaining("Malformed stack trace element");
    }

    @Test
    void shouldRoundTripApplicationFailure() {
        var exception = new ApplicationFailureException("app error", null, true);
        exception.setStackTrace(new StackTraceElement[0]);

        final Failure failure = FailureConverter.toFailure(exception);
        final FailureException restored = FailureConverter.toException(failure);

        assertThat(restored).isInstanceOf(ApplicationFailureException.class);
        assertThat(restored.getOriginalMessage()).isEqualTo("app error");
        assertThat(((ApplicationFailureException) restored).isTerminal()).isTrue();
    }

    @Test
    void shouldRoundTripInternalFailure() {
        var exception = new InternalFailureException("internal error");

        final Failure failure = FailureConverter.toFailure(exception);
        final FailureException restored = FailureConverter.toException(failure);

        assertThat(restored).isInstanceOf(InternalFailureException.class);
        assertThat(restored.getMessage()).isEqualTo("internal error");
    }

    @Test
    void shouldRoundTripCauseStackTrace() {
        var cause = new ApplicationFailureException("root cause", null);
        cause.setStackTrace(new StackTraceElement[]{
                new StackTraceElement("com.example.Root", "<init>", "Root.java", 1),
        });
        var exception = new ApplicationFailureException("wrapper", cause);
        exception.setStackTrace(new StackTraceElement[]{
                new StackTraceElement("com.example.Wrapper", "wrap", "Wrapper.java", 10),
        });

        final Failure failure = FailureConverter.toFailure(exception);
        final FailureException restored = FailureConverter.toException(failure);

        assertThat(restored).isInstanceOf(ApplicationFailureException.class);
        assertThat(restored.getStackTrace()).hasSize(1);
        assertThat(restored.getStackTrace()[0].getClassName()).isEqualTo("com.example.Wrapper");

        assertThat(restored.getCause()).isInstanceOf(ApplicationFailureException.class);
        assertThat(restored.getCause().getStackTrace()).hasSize(1);
        assertThat(restored.getCause().getStackTrace()[0].getMethodName()).isEqualTo("<init>");
    }

    @Test
    void shouldConvertUnknownThrowableToApplicationFailure() {
        var exception = new RuntimeException("unknown");
        exception.setStackTrace(new StackTraceElement[0]);

        final Failure failure = FailureConverter.toFailure(exception);
        final FailureException restored = FailureConverter.toException(failure);

        assertThat(restored).isInstanceOf(ApplicationFailureException.class);
        assertThat(restored.getOriginalMessage()).isEqualTo("unknown");
        assertThat(((ApplicationFailureException) restored).isTerminal()).isFalse();
    }

}