/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.common.validation;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * A ValidationException may be thrown if the specified input fails validation.
 *
 * @author Steve Springett
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ValidationException extends Exception {

    private final Object input;
    private final String message;

    /**
     * Constructs a new ValidationException
     * @param input the input that failed validation
     * @param message the error message explaining why validation failed
     */
    public ValidationException(final Object input, final String message) {
        this.input = input;
        this.message = message;
    }

    /**
     * Returns the object that failed validation
     * @return the object that failed validation
     */
    public Object getInput() {
        return input;
    }

    /**
     * Returns the validation error message
     * @return an error message
     */
    public String getMessage() {
        return message;
    }

    @Override
    @JsonIgnore
    public Throwable getCause() {
        return super.getCause();
    }

    @Override
    @JsonIgnore
    public String getLocalizedMessage() {
        return super.getLocalizedMessage();
    }

    @Override
    @JsonIgnore
    public StackTraceElement[] getStackTrace() {
        return super.getStackTrace();
    }

}
