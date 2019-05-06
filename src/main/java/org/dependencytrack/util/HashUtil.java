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
package org.dependencytrack.util;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

public final class HashUtil {

    private HashUtil() { }

    public static String md5(final File file) {
        try (InputStream fis = Files.newInputStream(file.toPath())) {
            return org.apache.commons.codec.digest.DigestUtils.md5Hex(fis);
        } catch (IOException e){
            return null;
        }
    }

    public static String sha1(final File file) {
        try (InputStream fis = Files.newInputStream(file.toPath())) {
            return org.apache.commons.codec.digest.DigestUtils.sha1Hex(fis);
        } catch (IOException e){
            return null;
        }
    }

    public static String sha256(final File file) {
        try (InputStream fis = Files.newInputStream(file.toPath())) {
            return org.apache.commons.codec.digest.DigestUtils.sha256Hex(fis);
        } catch (IOException e){
            return null;
        }
    }

    public static String sha512(final File file) {
        try (InputStream fis = Files.newInputStream(file.toPath())) {
            return org.apache.commons.codec.digest.DigestUtils.sha512Hex(fis);
        } catch (IOException e){
            return null;
        }
    }

}
