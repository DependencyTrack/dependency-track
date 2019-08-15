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
package org.dependencytrack.parser.nvd;

import org.dependencytrack.model.Cpe;
import org.dependencytrack.model.ICpe;
import org.dependencytrack.model.VulnerableSoftware;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

public final class ModelConverter {

    private ModelConverter() {
    }

    public static ICpe convertCpe23Uri(ICpe cpe, String cpe23Uri) throws CpeParsingException, CpeEncodingException {
        us.springett.parsers.cpe.Cpe parsedCpe = CpeParser.parse(cpe23Uri);
        cpe.setCpe23(cpe23Uri);
        cpe.setCpe22(parsedCpe.toCpe22Uri());
        cpe.setPart(parsedCpe.getPart().getAbbreviation());
        cpe.setVendor(parsedCpe.getVendor());
        cpe.setProduct(parsedCpe.getProduct());
        cpe.setVersion(parsedCpe.getVersion());
        cpe.setUpdate(parsedCpe.getUpdate());
        cpe.setEdition(parsedCpe.getEdition());
        cpe.setLanguage(parsedCpe.getLanguage());
        cpe.setSwEdition(parsedCpe.getSwEdition());
        cpe.setTargetSw(parsedCpe.getTargetSw());
        cpe.setTargetHw(parsedCpe.getTargetHw());
        cpe.setOther(parsedCpe.getOther());
        return cpe;
    }

    public static Cpe convertCpe23UriToCpe(String cpe23Uri) throws CpeParsingException, CpeEncodingException {
        Cpe cpe = new Cpe();
        return (Cpe)convertCpe23Uri(cpe, cpe23Uri);
    }

    public static VulnerableSoftware convertCpe23UriToVulnerableSoftware(String cpe23Uri) throws CpeParsingException, CpeEncodingException {
        VulnerableSoftware vs = new VulnerableSoftware();
        return (VulnerableSoftware)convertCpe23Uri(vs, cpe23Uri);
    }
}
