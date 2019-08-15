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
package org.dependencytrack.model;

public interface ICpe {

    String getCpe22();
    void setCpe22(String cpe22);

    String getCpe23();
    void setCpe23(String cpe23);

    String getPart();
    void setPart(String part);

    String getVendor();
    void setVendor(String vendor);

    String getProduct();
    void setProduct(String product);

    String getVersion();
    void setVersion(String version);

    String getUpdate();
    void setUpdate(String update);

    String getEdition();
    void setEdition(String edition);

    String getLanguage();
    void setLanguage(String language);

    String getSwEdition();
    void setSwEdition(String swEdition);

    String getTargetSw();
    void setTargetSw(String targetSw);

    String getTargetHw();
    void setTargetHw(String targetHw);

    String getOther();
    void setOther(String other);
}
