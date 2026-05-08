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
package org.dependencytrack.notification.templating.pebble;

import com.google.protobuf.Any;
import com.google.protobuf.Message;
import com.google.protobuf.Timestamp;
import com.google.protobuf.util.JsonFormat;
import com.google.protobuf.util.Timestamps;
import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import org.dependencytrack.notification.api.templating.NotificationTemplate;
import org.dependencytrack.notification.api.templating.NotificationTemplateRenderer;
import org.dependencytrack.notification.api.templating.RenderedNotificationTemplate;
import org.dependencytrack.notification.proto.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.notification.proto.v1.BomProcessingFailedSubject;
import org.dependencytrack.notification.proto.v1.BomValidationFailedSubject;
import org.dependencytrack.notification.proto.v1.NewPolicyViolationsSummarySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitiesSummarySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerableDependencySubject;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.PolicyViolationAnalysisDecisionChangeSubject;
import org.dependencytrack.notification.proto.v1.PolicyViolationSubject;
import org.dependencytrack.notification.proto.v1.ProjectVulnAnalysisCompleteSubject;
import org.dependencytrack.notification.proto.v1.UserSubject;
import org.dependencytrack.notification.proto.v1.VexConsumedOrProcessedSubject;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

/**
 * A {@link NotificationTemplateRenderer} powered by Pebble.
 *
 * @since 5.0.0
 */
final class PebbleNotificationTemplateRenderer implements NotificationTemplateRenderer {

    private static final Supplier<@Nullable Object> NULL_SUPPLIER = () -> null;

    private final PebbleEngine pebbleEngine;
    private final @Nullable NotificationTemplate template;
    private final Map<String, Supplier<@Nullable Object>> contextVariableSuppliers;

    public PebbleNotificationTemplateRenderer(
            PebbleEngine pebbleEngine,
            @Nullable NotificationTemplate template,
            Map<String, Supplier<@Nullable Object>> contextVariableSuppliers) {
        this.pebbleEngine = requireNonNull(pebbleEngine, "pebbleEngine must not be null");
        this.template = template;
        this.contextVariableSuppliers = requireNonNull(
                contextVariableSuppliers, "contextVariableSuppliers must not be null");
    }

    @Override
    public @Nullable RenderedNotificationTemplate render(
            Notification notification,
            @Nullable Map<String, @Nullable Object> additionalContext) {
        requireNonNull(notification, "notification must not be null");
        if (template == null) {
            return null;
        }

        final PebbleTemplate compiledTemplate = pebbleEngine.getLiteralTemplate(template.content());

        final var templateCtx = new HashMap<String, @Nullable Object>();
        if (additionalContext != null) {
            templateCtx.putAll(additionalContext);
        }
        templateCtx.put("baseUrl", contextVariableSuppliers.getOrDefault("baseUrl", NULL_SUPPLIER).get());
        templateCtx.put("timestampEpochSeconds", Timestamps.toSeconds(notification.getTimestamp()));
        templateCtx.put("timestamp", format(notification.getTimestamp()));
        templateCtx.put("notification", notification);

        final Message subject;
        try {
            subject = extractSubject(notification);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to extract subject", e);
        }

        if (subject != null) {
            templateCtx.put("subject", subject);

            try {
                templateCtx.put("subjectJson", JsonFormat.printer().print(subject));
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to serialize subject as JSON", e);
            }
        }

        try (final var writer = new StringWriter()) {
            compiledTemplate.evaluate(writer, templateCtx);
            return new RenderedNotificationTemplate(writer.toString(), template.mimeType());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static final DateTimeFormatter TIMESTAMP_FORMATTER =
            new DateTimeFormatterBuilder()
                    .parseCaseInsensitive()
                    .appendInstant(3)
                    .toFormatter();

    private static String format(Timestamp protoTimestamp) {
        return TIMESTAMP_FORMATTER.format(Instant.ofEpochMilli(Timestamps.toMillis(protoTimestamp)));
    }

    private static @Nullable Message extractSubject(Notification notification) throws IOException {
        if (!notification.hasSubject()) {
            return null;
        }

        final Any subject = notification.getSubject();

        if (subject.is(NewVulnerabilitySubject.class)) {
            return subject.unpack(NewVulnerabilitySubject.class);
        } else if (subject.is(NewVulnerableDependencySubject.class)) {
            return subject.unpack(NewVulnerableDependencySubject.class);
        } else if (subject.is(VulnerabilityAnalysisDecisionChangeSubject.class)) {
            return subject.unpack(VulnerabilityAnalysisDecisionChangeSubject.class);
        } else if (subject.is(PolicyViolationAnalysisDecisionChangeSubject.class)) {
            return subject.unpack(PolicyViolationAnalysisDecisionChangeSubject.class);
        } else if (subject.is(BomConsumedOrProcessedSubject.class)) {
            return subject.unpack(BomConsumedOrProcessedSubject.class);
        } else if (subject.is(BomProcessingFailedSubject.class)) {
            return subject.unpack(BomProcessingFailedSubject.class);
        } else if (subject.is(BomValidationFailedSubject.class)) {
            return subject.unpack(BomValidationFailedSubject.class);
        } else if (subject.is(VexConsumedOrProcessedSubject.class)) {
            return subject.unpack(VexConsumedOrProcessedSubject.class);
        } else if (subject.is(PolicyViolationSubject.class)) {
            return subject.unpack(PolicyViolationSubject.class);
        } else if (subject.is(ProjectVulnAnalysisCompleteSubject.class)) {
            return subject.unpack(ProjectVulnAnalysisCompleteSubject.class);
        } else if (subject.is(UserSubject.class)) {
            return subject.unpack(UserSubject.class);
        } else if (subject.is(NewVulnerabilitiesSummarySubject.class)) {
            return subject.unpack(NewVulnerabilitiesSummarySubject.class);
        } else if (subject.is(NewPolicyViolationsSummarySubject.class)) {
            return subject.unpack(NewPolicyViolationsSummarySubject.class);
        }

        return null;
    }

}
