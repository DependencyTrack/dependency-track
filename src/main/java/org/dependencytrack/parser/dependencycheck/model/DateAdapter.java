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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.parser.dependencycheck.model;

import javax.xml.bind.annotation.adapters.XmlAdapter;
import java.text.SimpleDateFormat;
import java.text.ParseException;
import java.util.Date;
import java.util.TimeZone;

/**
 * XmlAdapter class used to convert date formats.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class DateAdapter extends XmlAdapter<String, Date> {

    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
    private final SimpleDateFormat dateFormatInstant = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
    {
        dateFormatInstant.setTimeZone(TimeZone.getTimeZone("UTC"));
    }


    @Override
    public String marshal(final Date v) throws Exception {
        return dateFormatInstant.format(v);
    }

    @Override
    public Date unmarshal(final String v) throws Exception {
        Date parsed;

        try {
            parsed = dateFormat.parse(v);
        } catch (ParseException err) {
            parsed = dateFormatInstant.parse(v);
        }
        return parsed;
    }

}
