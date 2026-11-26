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
package org.dependencytrack.vulndatasource.jvn;

import io.github.nscuro.versatile.Comparator;
import io.github.nscuro.versatile.Vers;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses JVN's free-text Japanese affected-version expressions (the {@code <VersionNumber>}
 * field of a MyJVN {@code AffectedItem}) into a structured result usable for CPE range matching.
 * <p>
 * JVN encodes affected versions as natural-language Japanese text separate from the (product-level)
 * CPE, so a precise range match requires translating that text into a {@code vers} range. This is
 * the precision differentiator over go-cve-dictionary/Vuls, which leaves JVN matches at product
 * level.
 * <p>
 * Supported forms (observed in real JVN data):
 * <ul>
 *   <li>{@code "X 未満"} / {@code "X より前"}          -&gt; &lt; X</li>
 *   <li>{@code "X 以下"} / {@code "X 以前"}            -&gt; &lt;= X</li>
 *   <li>{@code "X 以上"} / {@code "X 以降"}            -&gt; &gt;= X</li>
 *   <li>{@code "X より後"} / {@code "X 超"}           -&gt; &gt; X</li>
 *   <li>{@code "X 以上 Y 未満"}                        -&gt; &gt;= X, &lt; Y</li>
 *   <li>{@code "X から Y"} / {@code "X 〜 Y"}          -&gt; &gt;= X, &lt;= Y</li>
 *   <li>{@code "X およびそれ以前"}                     -&gt; &lt;= X</li>
 *   <li>{@code "X"} (bare single version)            -&gt; exact</li>
 *   <li>{@code "すべてのバージョン"}                   -&gt; all-versions range</li>
 *   <li>Multi-clause lists joined by {@code "、"}, {@code ","}, {@code "および"}, {@code "及び"},
 *       {@code "または"}, or {@code "又は"}         -&gt; combined {@code vers} range</li>
 * </ul>
 * Texts that fail to parse as-is get one salvage attempt with platform/edition qualifiers
 * stripped ({@code "5.0 (client)"}, {@code "3 (x86-64)"}, {@code "Version 1809 for x64-based
 * Systems"}, {@code "12.04 LTS"}, {@code "2013 SP1"} …) — NVD carries the same products with
 * these qualifiers in separate CPE attributes (edition/update/target hardware), so dropping
 * them from the version value matches NVD's representation. Only known qualifier vocabulary is
 * stripped, and never from a text that already parsed, so no version value is ever invented.
 * <p>
 * Anything else (unrecognised wording, trailing qualifiers outside the known vocabulary,
 * contradictory bounds) yields {@link Unparseable} so the caller can degrade to a product-level
 * match rather than guess.
 *
 * @since 5.1.0
 */
public final class JvnVersionParser {

    /** Outcome of parsing a JVN version expression. */
    public sealed interface Result permits ExactVersion, VersionRange, Unparseable {}

    /** A single, exact affected version. */
    public record ExactVersion(String version) implements Result {}

    /** A structured affected-version range. */
    public record VersionRange(Vers vers) implements Result {}

    /** The expression could not be interpreted; caller should degrade to product-level. */
    public record Unparseable(String reason) implements Result {}

    // A version token: starts with an alphanumeric, may contain '.', '_', '-' and alphanumerics.
    // Covers semver (1.2.3), zero-padded (02.004.001.000) and Hitachi-style (11-40, 06-50-a).
    private static final String V = "[0-9A-Za-z][0-9A-Za-z._-]*";

    private static final Pattern GTE = Pattern.compile("(" + V + ")\\s*(?:以上|以降)");
    private static final Pattern GT = Pattern.compile("(" + V + ")\\s*(?:より後|を超える|超)");
    private static final Pattern LT = Pattern.compile("(" + V + ")\\s*(?:未満|より前)");
    private static final Pattern LTE = Pattern.compile("(" + V + ")\\s*(?:以下|以前)");
    private static final Pattern AND_BEFORE = Pattern.compile("(" + V + ")\\s*およびそれ以前");
    private static final Pattern AND_AFTER = Pattern.compile("(" + V + ")\\s*およびそれ以降");
    // "X から Y (まで)" or "X 〜 Y" (wave dash) — inclusive range.
    private static final Pattern FROM_TO = Pattern.compile("(" + V + ")\\s*(?:から|[〜～~])\\s*(" + V + ")\\s*(?:まで)?");
    private static final Pattern SINGLE = Pattern.compile("^\\s*(" + V + ")\\s*$");
    // Cisco-style version strings ("11.1(15)ca", "12.0(3.4)T1") carry a parenthesized build
    // number inside the version. NVD stores these verbatim as CPE version values, so they are
    // taken as exact versions rather than stripped.
    private static final Pattern PAREN_BUILD_VERSION =
            Pattern.compile("^\\s*(\\d[\\d.]*\\([0-9A-Za-z.]+\\)[0-9A-Za-z]*)\\s*$");

    // Separates multiple range or version clauses while keeping "X およびそれ以前/以降" intact.
    private static final Pattern CLAUSE_SEPARATOR =
            Pattern.compile("(?:\\s*(?:[、,]|および(?!\\s*それ以[前後])|及び|または|又は)\\s*)+");

    private record BoundPattern(Pattern pattern, Comparator comparator) {}

    private static final List<BoundPattern> BOUND_PATTERNS = List.of(
            new BoundPattern(AND_BEFORE, Comparator.LESS_THAN_OR_EQUAL),
            new BoundPattern(AND_AFTER, Comparator.GREATER_THAN_OR_EQUAL),
            new BoundPattern(GTE, Comparator.GREATER_THAN_OR_EQUAL),
            new BoundPattern(GT, Comparator.GREATER_THAN),
            new BoundPattern(LT, Comparator.LESS_THAN),
            new BoundPattern(LTE, Comparator.LESS_THAN_OR_EQUAL));

    // JVN spells "all versions" out in Japanese instead of using a range expression.
    private static final Pattern ALL_VERSIONS = Pattern.compile("^(?:すべてのバージョン|全てのバージョン|全バージョン)$");

    // Platform/edition/packaging words that JVN appends to version texts but that carry no
    // version information (NVD encodes them in separate CPE attributes). Only these are
    // eligible for salvage-stripping; anything else stays unparseable.
    private static final String QUALIFIER_WORDS =
            "x86(?:[-_]64)?|x64|amd64|ia64|arm64|itanium|sparc|client|server|desktop|workstation"
                    + "|es|as|ws|core|editions?|installation|installed";
    private static final Pattern TRAILING_PAREN_QUALIFIER = Pattern.compile(
            "\\s*[（(][^（）()]*(?:\\b(?:" + QUALIFIER_WORDS + ")\\b" + "|ビット|エディション|インストール|販売|版)[^（）()]*[）)]\\s*$",
            Pattern.CASE_INSENSITIVE);
    // "… for x64-based Systems", "… for 32-bit systems SP2", "… for 64-bit editions".
    private static final Pattern TRAILING_PLATFORM_PHRASE =
            Pattern.compile("\\s+for\\s+[\\w -]*(?:systems?|editions?)(\\s+SP\\d+)?\\s*$", Pattern.CASE_INSENSITIVE);
    // Bare trailing qualifier tokens: "12.04 LTS", "11 Express", "2013 SP1", "2013 RT".
    private static final Pattern TRAILING_QUALIFIER_TOKEN =
            Pattern.compile("\\s+(?:LTS|RT|Express|Gold|Editions?|SP\\d+)\\s*$", Pattern.CASE_INSENSITIVE);
    // Leading qualifier words in front of the version value: "Version 1809" (left over after
    // stripping "for x64-based Systems"), "- Standard Edition Version 4", "LTSC 2021".
    private static final Pattern LEADING_QUALIFIER_WORDS = Pattern.compile(
            "^[-\\s]*(?:(?:Standard|Web|Light|Professional|Enterprise|Datacenter|Core) )*"
                    + "(?:Edition )?(?:Version |LTSC )",
            Pattern.CASE_INSENSITIVE);

    private JvnVersionParser() {}

    /**
     * @param rawText The JVN {@code VersionNumber} text.
     * @param scheme  The {@code vers} versioning scheme to build the range with
     *                (typically {@code "generic"} for CPE-identified products).
     * @return The parsed {@link Result}.
     */
    public static Result parse(final String rawText, final String scheme) {
        if (rawText == null) {
            return new Unparseable("null");
        }

        // Normalise full-width spaces and collapse whitespace.
        final String text = rawText.replace('　', ' ').trim().replaceAll("\\s+", " ");
        if (text.isEmpty()) {
            return new Unparseable("empty");
        }

        if (ALL_VERSIONS.matcher(text).matches()) {
            try {
                return new VersionRange(Vers.builder(scheme)
                        .withConstraint(Comparator.WILDCARD, null)
                        .build());
            } catch (RuntimeException e) {
                return new Unparseable("vers build failed: " + e.getMessage());
            }
        }

        final Result result = parseCore(text, scheme);
        if (!(result instanceof Unparseable)) {
            return result;
        }

        final String stripped = stripQualifiers(text);
        if (!stripped.isEmpty() && !stripped.equals(text)) {
            final Result salvaged = parseCore(stripped, scheme);
            if (!(salvaged instanceof Unparseable)) {
                return salvaged;
            }
        }
        return result;
    }

    /**
     * Removes trailing platform/edition qualifiers (and a leading {@code "Version "} left over
     * after stripping) so texts like {@code "5.0 (client)"} or {@code "Version 1809 for
     * x64-based Systems"} can be retried as plain version expressions. Returns the text
     * unchanged when no known qualifier matches; may return an empty string when the text was
     * nothing but qualifiers (e.g. {@code "(Server Core installation)"}).
     */
    private static String stripQualifiers(final String text) {
        String current = text;
        while (true) {
            String next = TRAILING_PAREN_QUALIFIER.matcher(current).replaceFirst("");
            next = TRAILING_PLATFORM_PHRASE.matcher(next).replaceFirst("");
            next = TRAILING_QUALIFIER_TOKEN.matcher(next).replaceFirst("");
            if (next.equals(current)) {
                break;
            }
            current = next;
        }
        return LEADING_QUALIFIER_WORDS.matcher(current).replaceFirst("").trim();
    }

    private static Result parseCore(final String text, final String scheme) {
        final String[] clauses = CLAUSE_SEPARATOR.split(text, -1);
        for (final String clause : clauses) {
            if (clause.isEmpty()) {
                return new Unparseable("empty clause: " + text);
            }
        }

        if (clauses.length == 1) {
            final String exact = matchExactVersion(clauses[0]);
            if (exact != null) {
                return new ExactVersion(exact);
            }
        }

        try {
            final var builder = Vers.builder(scheme);
            for (final String clause : clauses) {
                if (!parseClause(clause, builder)) {
                    return new Unparseable("no recognised bound: " + text);
                }
            }
            return new VersionRange(builder.build().validate());
        } catch (RuntimeException e) {
            return new Unparseable("vers build failed: " + e.getMessage());
        }
    }

    private static @Nullable String matchExactVersion(final String clause) {
        final Matcher single = SINGLE.matcher(clause);
        if (single.matches()) {
            return single.group(1);
        }
        final Matcher parenBuild = PAREN_BUILD_VERSION.matcher(clause);
        if (parenBuild.matches()) {
            return parenBuild.group(1);
        }
        return null;
    }

    private static boolean parseClause(final String clause, final Vers.Builder builder) {
        final String exact = matchExactVersion(clause);
        if (exact != null && containsDigit(exact)) {
            builder.withConstraint(Comparator.EQUAL, exact);
            return true;
        }

        boolean matchedAny = false;
        int pos = 0;
        final int len = clause.length();
        final Matcher fromToMatcher = FROM_TO.matcher(clause);
        while (pos < len) {
            while (pos < len && Character.isWhitespace(clause.charAt(pos))) {
                pos++;
            }
            if (pos >= len) {
                break;
            }
            fromToMatcher.region(pos, len);
            if (fromToMatcher.lookingAt()) {
                builder.withConstraint(Comparator.GREATER_THAN_OR_EQUAL, fromToMatcher.group(1));
                builder.withConstraint(Comparator.LESS_THAN_OR_EQUAL, fromToMatcher.group(2));
                pos = fromToMatcher.end();
                matchedAny = true;
                continue;
            }
            boolean matched = false;
            for (final BoundPattern rule : BOUND_PATTERNS) {
                final Matcher m = rule.pattern().matcher(clause).region(pos, len);
                if (m.lookingAt()) {
                    builder.withConstraint(rule.comparator(), m.group(1));
                    pos = m.end();
                    matched = true;
                    matchedAny = true;
                    break;
                }
            }
            if (!matched) {
                return false;
            }
        }
        return matchedAny;
    }

    private static boolean containsDigit(final String s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.isDigit(s.charAt(i))) {
                return true;
            }
        }
        return false;
    }
}
