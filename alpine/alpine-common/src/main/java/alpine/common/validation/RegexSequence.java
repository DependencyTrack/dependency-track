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

/**
 * RegexSequence contains a library of commonly used regular expressions
 * used to validate untrusted input.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class RegexSequence {

    /**
     * Private constructor
     */
    private RegexSequence() { }

    public static class Definition {
        public static final String BOOLEAN = "^(true|false|yes|no|on|off|enabled|disabled|1|0)$";
        public static final String BOOLEAN_TRUE = "^(true|yes|on|enabled|1)$";
        public static final String BOOLEAN_FALSE = "^(false|no|off|disabled|0)$";

        public static final String HTTP_SCHEME = "^(http|https)$";
        public static final String HTTP_SERVER_NAME = "^[a-zA-Z0-9_.\\-]*$";
        public static final String HTTP_SERVLET_PATH = "^[a-zA-Z0-9.\\-\\/_]*$";
        public static final String HTTP_CHAR_ENCODING = "^[A-Za-z0-9_-]*$";
        public static final String HTTP_PARAMETER_NAME = "^[\\w]{1,32}$";
        public static final String HTTP_PARAMETER_VALUE = "^[\\w.\\-\\/+=@ ]*$";
        public static final String HTTP_COOKIE_NAME = "^[a-zA-Z0-9\\-_]{1,32}$";
        public static final String HTTP_COOKIE_VALUE = "^[a-zA-Z0-9\\-\\/+=_ ]*$";
        public static final String HTTP_HEADER_NAME = "^[a-zA-Z0-9\\-_]{1,32}$";
        public static final String HTTP_HEADER_VALUE = "^[a-zA-Z0-9()\\-=\\*\\.\\?;,+\\/:&_ ]*$";
        public static final String HTTP_CONTEXT_PATH = "^\\/?[a-zA-Z0-9.\\-\\/_]*$";
        public static final String HTTP_PATH = "^[a-zA-Z0-9.\\-_]*$";
        public static final String HTTP_QUERY_STRING = "^[\\w()\\-=\\*\\.\\?;,+\\/:& %]*$";
        public static final String HTTP_URI = "^[\\w()\\-=\\*\\.\\?;,+\\/:&@ ]*$";
        public static final String HTTP_URL = "^.*$";
        public static final String HTTP_JSESSION_ID = "^[A-Z0-9]{10,128}$";

        public static final String FS_FILE_NAME = "^[\\p{Alnum}!@#$%^&{}\\[\\]()_+\\-=,.~'` ]{1,255}$";
        public static final String FS_DIRECTORY_NAME = "^[\\p{Alnum}:/\\\\!@#$%^&{}\\[\\]()_+\\-=,.~'` ]{1,255}$";

        public static final String ALPHA = "^\\p{Alpha}*$";
        public static final String ALPHA_LOWERCASE = "^\\p{Lower}*$";
        public static final String ALPHA_UPPERCASE = "^\\p{Upper}*$";
        public static final String NUMERIC = "^[-+]?\\p{Digit}*\\.?\\p{Digit}+([eE][-+]?\\p{Digit}+)?$";
        public static final String ALPHA_NUMERIC = "^\\p{Alnum}*$";
        public static final String WORD_CHARS = "^[a-zA-Z_0-9]*$";
        public static final String PRINTABLE_CHARS = "^[\\p{IsWhite_Space}\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}]*$";
        public static final String PRINTABLE_CHARS_PLUS = "^[\\p{IsWhite_Space}\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}\\n\\r\\t]*$";
        public static final String NOT_CONTROL_CHARS = "^[^\\x00-\\x1F\\x7F]*$";

        public static final String HEXADECIMAL = "^[A-Fa-f0-9]*$";
        public static final String BINARY = "^[0-1]*$";
        public static final String UUID = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
        public static final String STRING_IDENTIFIER = "^[a-zA-Z0-9_.\\-+]*$";

        public static final String HASH_MD5 = "^[0-9a-f]{32}$";
        public static final String HASH_SHA1 = "^[0-9a-f]{40}$";
        public static final String HASH_SHA256 = "^[0-9a-f]{64}$";
        public static final String HASH_SHA384 = "^[0-9a-f]{96}$";
        public static final String HASH_SHA512 = "^[0-9a-f]{128}$";
        public static final String HASH_MD5_SHA1 = "^([0-9a-f]{32}|[0-9a-f]{40})$";
        public static final String HASH_MD5_SHA1_SHA256_SHA384_SHA512 = "^([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{96}|[0-9a-f]{128})$";

        public static final String SAFESTRING = "^[\\p{L}\\p{N}.]{0,1024}$";
        public static final String HTML_HEX_CODE = "^#?([a-f]|[A-F]|[0-9]){3}(([a-f]|[A-F]|[0-9]){3})?$";
        public static final String EMAIL_ADDRESS = "^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\\.[a-zA-Z]{2,4}$";
        public static final String IPV4_ADDRESS = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";
        public static final String MAC_ADDRESS = "^([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])$";
        public static final String RFC_1918_NON_ROUTABLE_IP = "^(((25[0-5]|2[0-4][0-9]|19[0-1]|19[3-9]|18[0-9]|17[0-1]|17[3-9]|1[0-6][0-9]|1[1-9]|[2-9][0-9]|[0-9])\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]))|(192\\.(25[0-5]|2[0-4][0-9]|16[0-7]|169|1[0-5][0-9]|1[7-9][0-9]|[1-9][0-9]|[0-9]))|(172\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|1[0-5]|3[2-9]|[4-9][0-9]|[0-9])))\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$";
        public static final String URL = "^((((https?|ftps?|sftp|imap|rtsp|rtmp|sip|sips|git|ssh|telnet|nntp|file)://)|(mailto:|news:))(%[0-9A-Fa-f]{2}|[-()_.!~*';/?:@&=+$,A-Za-z0-9])+)([).!';/?:,][[:blank:]])?$";
        public static final String SOCIAL_SECURITY_NUMBER = "^(?!000)([0-6]\\d{2}|7([0-6]\\d|7[012]))([ -]?)(?!00)\\d\\d\\3(?!0000)\\d{4}$";
        public static final String CREDIT_CARD_VISA = "^4[0-9]{12}(?:[0-9]{3})?$";
        public static final String CREDIT_CARD_MASTERCARD = "^5[1-5][0-9]{14}$";
        public static final String CREDIT_CARD_AMEX = "^3[47][0-9]{13}$";
        public static final String CREDIT_CARD_DINERSCLUB = "^3(?:0[0-5]|[68][0-9])[0-9]{11}$";
        public static final String CREDIT_CARD_DISCOVER = "^6(?:011|5[0-9]{2})[0-9]{12}$";
        public static final String CREDIT_CARD_JCB = "^(?:2131|1800|35\\d{3})\\d{11}$";
    }

    public static class Pattern {
        public static final java.util.regex.Pattern BOOLEAN = java.util.regex.Pattern.compile(RegexSequence.Definition.BOOLEAN, java.util.regex.Pattern.CASE_INSENSITIVE);
        public static final java.util.regex.Pattern BOOLEAN_TRUE = java.util.regex.Pattern.compile(RegexSequence.Definition.BOOLEAN_TRUE, java.util.regex.Pattern.CASE_INSENSITIVE);
        public static final java.util.regex.Pattern BOOLEAN_FALSE = java.util.regex.Pattern.compile(RegexSequence.Definition.BOOLEAN_FALSE, java.util.regex.Pattern.CASE_INSENSITIVE);

        public static final java.util.regex.Pattern HTTP_SCHEME = java.util.regex.Pattern.compile(RegexSequence.Definition.HTTP_SCHEME);
        public static final java.util.regex.Pattern HTTP_SERVER_NAME = java.util.regex.Pattern.compile(RegexSequence.Definition.HTTP_SERVER_NAME);
        public static final java.util.regex.Pattern HTTP_SERVLET_PATH = java.util.regex.Pattern.compile(RegexSequence.Definition.HTTP_SERVLET_PATH);
        public static final java.util.regex.Pattern HTTP_CHAR_ENCODING = java.util.regex.Pattern.compile(RegexSequence.Definition.HTTP_CHAR_ENCODING);
        public static final java.util.regex.Pattern HTTP_PARAMETER_NAME = java.util.regex.Pattern.compile(RegexSequence.Definition.HTTP_PARAMETER_NAME, java.util.regex.Pattern.UNICODE_CHARACTER_CLASS);
        public static final java.util.regex.Pattern HTTP_PARAMETER_VALUE = java.util.regex.Pattern.compile(RegexSequence.Definition.HTTP_PARAMETER_VALUE, java.util.regex.Pattern.UNICODE_CHARACTER_CLASS);
        public static final java.util.regex.Pattern HTTP_COOKIE_NAME = java.util.regex.Pattern.compile(RegexSequence.Definition.HTTP_COOKIE_NAME);
        public static final java.util.regex.Pattern HTTP_COOKIE_VALUE = java.util.regex.Pattern.compile(RegexSequence.Definition.HTTP_COOKIE_VALUE);
        public static final java.util.regex.Pattern HTTP_HEADER_NAME = java.util.regex.Pattern.compile(RegexSequence.Definition.HTTP_HEADER_NAME);
        public static final java.util.regex.Pattern HTTP_HEADER_VALUE = java.util.regex.Pattern.compile(RegexSequence.Definition.HTTP_HEADER_VALUE);
        public static final java.util.regex.Pattern HTTP_CONTEXT_PATH = java.util.regex.Pattern.compile(RegexSequence.Definition.HTTP_CONTEXT_PATH);
        public static final java.util.regex.Pattern HTTP_PATH = java.util.regex.Pattern.compile(RegexSequence.Definition.HTTP_PATH);
        public static final java.util.regex.Pattern HTTP_QUERY_STRING = java.util.regex.Pattern.compile(RegexSequence.Definition.HTTP_QUERY_STRING, java.util.regex.Pattern.UNICODE_CHARACTER_CLASS);
        public static final java.util.regex.Pattern HTTP_URI = java.util.regex.Pattern.compile(RegexSequence.Definition.HTTP_URI, java.util.regex.Pattern.UNICODE_CHARACTER_CLASS);
        public static final java.util.regex.Pattern HTTP_URL = java.util.regex.Pattern.compile(RegexSequence.Definition.HTTP_URL);
        public static final java.util.regex.Pattern HTTP_JSESSION_ID = java.util.regex.Pattern.compile(RegexSequence.Definition.HTTP_JSESSION_ID);

        public static final java.util.regex.Pattern FS_FILE_NAME = java.util.regex.Pattern.compile(RegexSequence.Definition.FS_FILE_NAME, java.util.regex.Pattern.UNICODE_CHARACTER_CLASS);
        public static final java.util.regex.Pattern FS_DIRECTORY_NAME = java.util.regex.Pattern.compile(RegexSequence.Definition.FS_DIRECTORY_NAME, java.util.regex.Pattern.UNICODE_CHARACTER_CLASS);

        public static final java.util.regex.Pattern ALPHA = java.util.regex.Pattern.compile(RegexSequence.Definition.ALPHA, java.util.regex.Pattern.UNICODE_CHARACTER_CLASS);
        public static final java.util.regex.Pattern ALPHA_LOWERCASE = java.util.regex.Pattern.compile(RegexSequence.Definition.ALPHA_LOWERCASE, java.util.regex.Pattern.UNICODE_CHARACTER_CLASS);
        public static final java.util.regex.Pattern ALPHA_UPPERCASE = java.util.regex.Pattern.compile(RegexSequence.Definition.ALPHA_UPPERCASE, java.util.regex.Pattern.UNICODE_CHARACTER_CLASS);
        public static final java.util.regex.Pattern NUMERIC = java.util.regex.Pattern.compile(RegexSequence.Definition.NUMERIC);
        public static final java.util.regex.Pattern ALPHA_NUMERIC = java.util.regex.Pattern.compile(RegexSequence.Definition.ALPHA_NUMERIC, java.util.regex.Pattern.UNICODE_CHARACTER_CLASS);
        public static final java.util.regex.Pattern WORD_CHARS = java.util.regex.Pattern.compile(RegexSequence.Definition.WORD_CHARS, java.util.regex.Pattern.UNICODE_CHARACTER_CLASS);
        public static final java.util.regex.Pattern PRINTABLE_CHARS = java.util.regex.Pattern.compile(RegexSequence.Definition.PRINTABLE_CHARS, java.util.regex.Pattern.UNICODE_CHARACTER_CLASS);
        public static final java.util.regex.Pattern PRINTABLE_CHARS_PLUS = java.util.regex.Pattern.compile(RegexSequence.Definition.PRINTABLE_CHARS_PLUS, java.util.regex.Pattern.UNICODE_CHARACTER_CLASS);
        public static final java.util.regex.Pattern NOT_CONTROL_CHARS = java.util.regex.Pattern.compile(Definition.NOT_CONTROL_CHARS);
        public static final java.util.regex.Pattern HEXADECIMAL = java.util.regex.Pattern.compile(RegexSequence.Definition.HEXADECIMAL);
        public static final java.util.regex.Pattern BINARY = java.util.regex.Pattern.compile(RegexSequence.Definition.BINARY);
        public static final java.util.regex.Pattern UUID = java.util.regex.Pattern.compile(RegexSequence.Definition.UUID);
        public static final java.util.regex.Pattern STRING_IDENTIFIER = java.util.regex.Pattern.compile(RegexSequence.Definition.STRING_IDENTIFIER);

        public static final java.util.regex.Pattern HASH_MD5 = java.util.regex.Pattern.compile(RegexSequence.Definition.HASH_MD5);
        public static final java.util.regex.Pattern HASH_SHA1 = java.util.regex.Pattern.compile(RegexSequence.Definition.HASH_SHA1);
        public static final java.util.regex.Pattern HASH_SHA256 = java.util.regex.Pattern.compile(RegexSequence.Definition.HASH_SHA256);
        public static final java.util.regex.Pattern HASH_SHA384 = java.util.regex.Pattern.compile(RegexSequence.Definition.HASH_SHA384);
        public static final java.util.regex.Pattern HASH_SHA512 = java.util.regex.Pattern.compile(RegexSequence.Definition.HASH_SHA512);
        public static final java.util.regex.Pattern HASH_MD5_SHA1 = java.util.regex.Pattern.compile(RegexSequence.Definition.HASH_MD5_SHA1);
        public static final java.util.regex.Pattern HASH_MD5_SHA1_SHA256_SHA512 = java.util.regex.Pattern.compile(RegexSequence.Definition.HASH_MD5_SHA1_SHA256_SHA384_SHA512);

        public static final java.util.regex.Pattern SAFESTRING = java.util.regex.Pattern.compile(RegexSequence.Definition.SAFESTRING);
        public static final java.util.regex.Pattern HTML_HEX_CODE = java.util.regex.Pattern.compile(RegexSequence.Definition.HTML_HEX_CODE);
        public static final java.util.regex.Pattern EMAIL_ADDRESS = java.util.regex.Pattern.compile(RegexSequence.Definition.EMAIL_ADDRESS);
        public static final java.util.regex.Pattern IPV4_ADDRESS = java.util.regex.Pattern.compile(RegexSequence.Definition.IPV4_ADDRESS);
        public static final java.util.regex.Pattern MAC_ADDRESS = java.util.regex.Pattern.compile(RegexSequence.Definition.MAC_ADDRESS);
        public static final java.util.regex.Pattern RFC_1918_NON_ROUTABLE_IP = java.util.regex.Pattern.compile(RegexSequence.Definition.RFC_1918_NON_ROUTABLE_IP);
        public static final java.util.regex.Pattern URL = java.util.regex.Pattern.compile(RegexSequence.Definition.URL);
        public static final java.util.regex.Pattern SOCIAL_SECURITY_NUMBER = java.util.regex.Pattern.compile(RegexSequence.Definition.SOCIAL_SECURITY_NUMBER);
        public static final java.util.regex.Pattern CREDIT_CARD_VISA = java.util.regex.Pattern.compile(RegexSequence.Definition.CREDIT_CARD_VISA);
        public static final java.util.regex.Pattern CREDIT_CARD_MASTERCARD = java.util.regex.Pattern.compile(RegexSequence.Definition.CREDIT_CARD_MASTERCARD);
        public static final java.util.regex.Pattern CREDIT_CARD_AMEX = java.util.regex.Pattern.compile(RegexSequence.Definition.CREDIT_CARD_AMEX);
        public static final java.util.regex.Pattern CREDIT_CARD_DINERSCLUB = java.util.regex.Pattern.compile(RegexSequence.Definition.CREDIT_CARD_DINERSCLUB);
        public static final java.util.regex.Pattern CREDIT_CARD_DISCOVER = java.util.regex.Pattern.compile(RegexSequence.Definition.CREDIT_CARD_DISCOVER);
        public static final java.util.regex.Pattern CREDIT_CARD_JCB = java.util.regex.Pattern.compile(RegexSequence.Definition.CREDIT_CARD_JCB);
    }

}
