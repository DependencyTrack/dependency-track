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
package org.dependencytrack.notification.api;

import com.google.protobuf.DescriptorProtos;
import com.google.protobuf.Descriptors;
import com.google.protobuf.DynamicMessage;
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.notification.proto.v1.Component;
import org.dependencytrack.notification.proto.v1.Group;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.PolicyViolation;
import org.dependencytrack.notification.proto.v1.PolicyViolationSubject;
import org.dependencytrack.notification.proto.v1.PolicyViolationUpdatedSubject;
import org.dependencytrack.notification.proto.v1.Project;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.notification.api.NotificationFactory.createPolicyViolationNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createPolicyViolationUpdatedNotification;

class PolicyViolationUpdatedNotificationTest {

    private static Stream<Arguments> messageChanges() {
        return Stream.of(
                Arguments.of("CVE-A", "CVE-A,CVE-B"),
                Arguments.of(null, "CVE-B"),
                Arguments.of("CVE-A", null),
                Arguments.of("", "CVE-B"));
    }

    @ParameterizedTest
    @MethodSource("messageChanges")
    void shouldRoundTripStructuredChangesAndNullPresence(String previous, String current) throws Exception {
        final var project =
                Project.newBuilder().setUuid("project-id").setName("app").build();
        final var component =
                Component.newBuilder().setUuid("component-id").setName("lib").build();
        final var violation = PolicyViolation.newBuilder()
                .setUuid("stable-violation-id")
                .setType("SECURITY")
                .setMessage("stale hydration must not override the captured change")
                .build();
        final var changedAt = Timestamps.fromMillis(1149573966666L);

        final Notification notification =
                createPolicyViolationUpdatedNotification(project, component, violation, previous, current, changedAt);
        final var subject = Notification.parseFrom(notification.toByteArray())
                .getSubject()
                .unpack(PolicyViolationUpdatedSubject.class);

        assertThat(notification.getGroup()).isEqualTo(Group.GROUP_POLICY_VIOLATION_UPDATED);
        assertThat(notification.getId()).isNotBlank();
        assertThat(notification.hasTimestamp()).isTrue();
        assertThat(subject.getProject()).isEqualTo(project);
        assertThat(subject.getComponent()).isEqualTo(component);
        assertThat(subject.getPolicyViolation().getUuid()).isEqualTo(violation.getUuid());
        assertThat(subject.getChangedAt()).isEqualTo(changedAt);
        assertThat(subject.hasAnalysisState()).isFalse();
        assertThat(subject.hasSuppressed()).isFalse();
        assertThat(subject.hasPreviousMessage()).isEqualTo(previous != null);
        assertThat(subject.hasCurrentMessage()).isEqualTo(current != null);
        assertThat(subject.getPreviousMessage()).isEqualTo(previous == null ? "" : previous);
        assertThat(subject.getCurrentMessage()).isEqualTo(current == null ? "" : current);
        assertThat(subject.getPolicyViolation().hasMessage()).isEqualTo(current != null);
        assertThat(subject.getPolicyViolation().getMessage()).isEqualTo(current == null ? "" : current);
    }

    @Test
    void shouldPreserveCreationEventContract() throws Exception {
        final var violation = PolicyViolation.newBuilder()
                .setType("SECURITY")
                .setMessage("CVE-A")
                .build();
        final Notification created = createPolicyViolationNotification(
                Project.newBuilder().setName("app").build(), Component.getDefaultInstance(), violation);

        assertThat(Group.GROUP_POLICY_VIOLATION.getNumber()).isEqualTo(15);
        assertThat(created.getGroup()).isEqualTo(Group.GROUP_POLICY_VIOLATION);
        assertThat(created.getSubject().unpack(PolicyViolationSubject.class).getPolicyViolation())
                .isEqualTo(violation);
        assertThat(Group.GROUP_POLICY_VIOLATION_UPDATED.getNumber()).isEqualTo(25);
    }

    @Test
    void shouldBeReadableAndPreservedByPreviousProtobufSchema() throws Exception {
        final var descriptor = Notification.getDescriptor().getFile();
        final var oldSchema = descriptor.toProto().toBuilder().clearEnumType().clearMessageType();
        for (final var enumType : descriptor.toProto().getEnumTypeList()) {
            final var oldEnum = enumType.toBuilder().clearValue();
            for (final var value : enumType.getValueList()) {
                if (!value.getName().startsWith("GROUP_POLICY_VIOLATION_UPDATED")) {
                    oldEnum.addValue(value);
                }
            }
            oldSchema.addEnumType(oldEnum);
        }
        for (final DescriptorProtos.DescriptorProto message :
                descriptor.toProto().getMessageTypeList()) {
            if (!message.getName().equals("PolicyViolationUpdatedSubject")) {
                oldSchema.addMessageType(message);
            }
        }
        final var oldDescriptor = Descriptors.FileDescriptor.buildFrom(
                oldSchema.build(), descriptor.getDependencies().toArray(Descriptors.FileDescriptor[]::new));
        final var oldNotificationDescriptor = oldDescriptor.findMessageTypeByName("Notification");
        final Notification updated = TestNotificationFactory.createPolicyViolationUpdatedTestNotification();

        final DynamicMessage oldConsumer = DynamicMessage.parseFrom(oldNotificationDescriptor, updated.toByteArray());
        final var group = (Descriptors.EnumValueDescriptor)
                oldConsumer.getField(oldNotificationDescriptor.findFieldByName("group"));
        assertThat(group.getNumber()).isEqualTo(25);
        assertThat(Notification.parseFrom(oldConsumer.toByteArray())).isEqualTo(updated);
    }

    private static Stream<Arguments> reviewContexts() {
        return Stream.of(
                Arguments.of(null, null, false),
                Arguments.of(null, false, false),
                Arguments.of("NOT_SET", false, false),
                Arguments.of("REJECTED", false, false),
                Arguments.of("APPROVED", null, true),
                Arguments.of("APPROVED", false, true),
                Arguments.of(null, true, true),
                Arguments.of("REJECTED", true, true),
                Arguments.of("APPROVED", true, true));
    }

    @ParameterizedTest
    @MethodSource("reviewContexts")
    void shouldSelectExactlyOneGroupAndPreserveReviewMetadata(
            @Nullable String state, @Nullable Boolean suppressed, boolean reviewed) throws Exception {
        final var violation = PolicyViolation.newBuilder()
                .setType("SECURITY")
                .setUuid("stable-id")
                .build();
        final Notification notification = createPolicyViolationUpdatedNotification(
                Project.newBuilder().setName("app").build(),
                Component.getDefaultInstance(),
                violation,
                "CVE-A",
                "CVE-A,CVE-B",
                Timestamps.fromMillis(1149573966666L),
                state,
                suppressed);
        final var subject = Notification.parseFrom(notification.toByteArray())
                .getSubject()
                .unpack(PolicyViolationUpdatedSubject.class);

        assertThat(notification.getGroup())
                .isEqualTo(
                        reviewed
                                ? Group.GROUP_POLICY_VIOLATION_UPDATED_REVIEWED
                                : Group.GROUP_POLICY_VIOLATION_UPDATED);
        assertThat(subject.hasAnalysisState()).isEqualTo(state != null);
        assertThat(subject.hasSuppressed()).isEqualTo(suppressed != null);
        assertThat(subject.getAnalysisState()).isEqualTo(state == null ? "" : state);
        assertThat(subject.getSuppressed()).isEqualTo(Boolean.TRUE.equals(suppressed));
        assertThat(subject.getPolicyViolation().getUuid()).isEqualTo("stable-id");
        assertThat(subject.getPolicyViolation().getMessage()).isEqualTo("CVE-A,CVE-B");
        if (reviewed) {
            assertThat(notification.getTitle()).contains("Reviewed Policy Violation Updated");
            assertThat(notification.getContent()).contains("review decision is retained");
        }
    }

    @Test
    void shouldPreserveReviewedMetadataWithPreviousUpdateSchema() throws Exception {
        final var descriptor = Notification.getDescriptor().getFile();
        final var oldSchema = descriptor.toProto().toBuilder().clearEnumType().clearMessageType();
        for (final var enumType : descriptor.toProto().getEnumTypeList()) {
            final var oldEnum = enumType.toBuilder().clearValue();
            for (final var value : enumType.getValueList()) {
                if (!value.getName().equals("GROUP_POLICY_VIOLATION_UPDATED_REVIEWED")) {
                    oldEnum.addValue(value);
                }
            }
            oldSchema.addEnumType(oldEnum);
        }
        for (final var message : descriptor.toProto().getMessageTypeList()) {
            if (!message.getName().equals("PolicyViolationUpdatedSubject")) {
                oldSchema.addMessageType(message);
                continue;
            }
            final var oldSubject = message.toBuilder().clearField().clearOneofDecl();
            message.getFieldList().stream()
                    .filter(field -> field.getNumber() <= 6)
                    .forEach(oldSubject::addField);
            message.getOneofDeclList().stream()
                    .filter(oneof -> !oneof.getName().equals("_analysis_state")
                            && !oneof.getName().equals("_suppressed"))
                    .forEach(oldSubject::addOneofDecl);
            oldSchema.addMessageType(oldSubject);
        }
        final var oldDescriptor = Descriptors.FileDescriptor.buildFrom(
                oldSchema.build(), descriptor.getDependencies().toArray(Descriptors.FileDescriptor[]::new));
        final var reviewed = TestNotificationFactory.createReviewedPolicyViolationUpdatedTestNotification();
        final var subject = reviewed.getSubject().unpack(PolicyViolationUpdatedSubject.class);
        final var oldSubject = DynamicMessage.parseFrom(
                oldDescriptor.findMessageTypeByName("PolicyViolationUpdatedSubject"), subject.toByteArray());
        assertThat(oldSubject.getUnknownFields().asMap()).containsKeys(7, 8);
        assertThat(PolicyViolationUpdatedSubject.parseFrom(oldSubject.toByteArray()))
                .isEqualTo(subject);
        final var oldNotificationDescriptor = oldDescriptor.findMessageTypeByName("Notification");
        final var oldNotification = DynamicMessage.parseFrom(oldNotificationDescriptor, reviewed.toByteArray());
        final var group = (Descriptors.EnumValueDescriptor)
                oldNotification.getField(oldNotificationDescriptor.findFieldByName("group"));
        assertThat(group.getNumber()).isEqualTo(26);
        assertThat(Notification.parseFrom(oldNotification.toByteArray())).isEqualTo(reviewed);
    }
}
