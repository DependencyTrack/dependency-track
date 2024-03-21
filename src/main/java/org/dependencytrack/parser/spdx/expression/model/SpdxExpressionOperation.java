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
import java.util.stream.Collectors;

/**
 * A SPDX expression operation with one of the SPDX operators as defined in the spec, and arguments
 * to that operator.
 * 
 * @author hborchardt
 * @since 4.9.0
 */
public class SpdxExpressionOperation {
    private SpdxOperator operator;
    private List<SpdxExpression> arguments;

    public SpdxExpressionOperation(SpdxOperator operator, List<SpdxExpression> arguments) {
        this.operator = operator;
        this.arguments = arguments;
    }

    public SpdxOperator getOperator() {
        return operator;
    }

    public void setOperator(SpdxOperator operator) {
        this.operator = operator;
    }

    public List<SpdxExpression> getArguments() {
        return arguments;
    }

    public void setArguments(List<SpdxExpression> arguments) {
        this.arguments = arguments;
    }

    @Override
    public String toString() {
        return operator + "("
                + arguments.stream().map(SpdxExpression::toString).collect(Collectors.joining(", ")) + ")";
    }
}
