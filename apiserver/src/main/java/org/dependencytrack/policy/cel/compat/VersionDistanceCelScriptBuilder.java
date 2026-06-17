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
package org.dependencytrack.policy.cel.compat;

import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.util.JsonFormat;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.proto.policy.v1.VersionDistance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VersionDistanceCelScriptBuilder implements CelPolicyScriptSourceBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(VersionDistanceCelScriptBuilder.class);

    @Override
    public String apply(PolicyCondition policyCondition) {
        return """
                component.version_distance("%s", %s)
                """.formatted(comparator(policyCondition.getOperator()), toProtoString(policyCondition.getValue()));
    }


    private String toProtoString(String conditionValue) {
        try {
            VersionDistance.Builder structBuilder = VersionDistance.newBuilder();
            JsonFormat.parser().ignoringUnknownFields().merge(conditionValue, structBuilder);
            return convertToString(structBuilder.build());
        } catch (InvalidProtocolBufferException e) {
            LOGGER.error("Invalid version distance proto {}", e);
            return convertToString(VersionDistance.newBuilder().build());
        }
    }

    private String convertToString(VersionDistance versionDistance) {
        StringBuilder sbf = new StringBuilder();
        if (!StringUtils.isEmpty(versionDistance.getEpoch())) {
            sbf.append("epoch:").append("\"").append(versionDistance.getEpoch()).append("\"").append(",");
        }
        sbf.append("major:").append("\"").append(versionDistance.getMajor()).append("\"").append(",");
        sbf.append("minor:").append("\"").append(versionDistance.getMinor()).append("\"").append(",");
        sbf.append("patch:").append("\"").append(versionDistance.getPatch()).append("\"");
        return "v1.VersionDistance{" + sbf + "}";
    }

    private String comparator(PolicyCondition.Operator operator) {
        return switch (operator) {
            case NUMERIC_GREATER_THAN -> ">";
            case NUMERIC_GREATER_THAN_OR_EQUAL -> ">=";
            case NUMERIC_EQUAL -> "==";
            case NUMERIC_NOT_EQUAL -> "!=";
            case NUMERIC_LESSER_THAN_OR_EQUAL -> "<=";
            case NUMERIC_LESS_THAN -> "<";
            default -> "";
        };
    }
}
