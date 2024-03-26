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
package org.dependencytrack.parser.spdx.expression.model;

import java.util.List;

/**
 * A node of an SPDX expression tree. If it is a leaf node, it contains a spdxLicenseId. If it is an
 * inner node, containss an operation.
 * 
 * @author hborchardt
 * @since 4.9.0
 */
public class SpdxExpression {
    public static final SpdxExpression INVALID = new SpdxExpression(null);
    public SpdxExpression(String spdxLicenseId) {
        this.spdxLicenseId = spdxLicenseId;
    }

    public SpdxExpression(SpdxOperator operator, List<SpdxExpression> arguments) {
        this.operation = new SpdxExpressionOperation(operator, arguments);
    }

    private SpdxExpressionOperation operation;
    private String spdxLicenseId;

    public SpdxExpressionOperation getOperation() {
        return operation;
    }

    public void setOperation(SpdxExpressionOperation operation) {
        this.operation = operation;
    }

    public String getSpdxLicenseId() {
        return spdxLicenseId;
    }

    public void setSpdxLicenseId(String spdxLicenseId) {
        this.spdxLicenseId = spdxLicenseId;
    }

    @Override
    public String toString() {
        if (this == INVALID) {
            return "INVALID";
        }
        if (spdxLicenseId != null) {
            return spdxLicenseId;
        }
        return operation.toString();
    }
}
