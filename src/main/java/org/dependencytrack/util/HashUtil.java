/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class HashUtil {

    private HashUtil() { }

    public static String md5(File file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            return org.apache.commons.codec.digest.DigestUtils.md5Hex(fis);
        } catch (IOException e){
            return null;
        }
    }

    public static String sha1(File file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            return org.apache.commons.codec.digest.DigestUtils.sha1Hex(fis);
        } catch (IOException e){
            return null;
        }
    }

    public static String sha256(File file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            return org.apache.commons.codec.digest.DigestUtils.sha256Hex(fis);
        } catch (IOException e){
            return null;
        }
    }

    public static String sha512(File file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            return org.apache.commons.codec.digest.DigestUtils.sha512Hex(fis);
        } catch (IOException e){
            return null;
        }
    }

}
