package org.dependencytrack.util;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.Collection;

import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_COMPONENTS_GROUPS_REGEX;
import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_COMPONENTS_NAMES_REGEX;
import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_COMPONENTS_MATCH_MODE;
import static org.junit.jupiter.api.Assertions.assertEquals;

class InternalComponentIdentificationUtilTest extends PersistenceCapableTest {

    public static Collection<Arguments> testParameters() {
        return Arrays.asList(
                // neither regexes nor group / name provided
                Arguments.of("", "", "", "", "OR", false),
                Arguments.of("", "", "", "", "AND", false),
                // Neither group nor name provided
                Arguments.of(".*", null, ".*", null, "OR", false),
                Arguments.of(".*", null, ".*", null, "AND", false),
                // group matches, name not provided
                Arguments.of(".*", "a", ".*", null, "OR", true),
                Arguments.of(".*", "a", ".*", null, "AND", false),
                // group not provided, name matches
                Arguments.of(".*", null, ".*", "a", "OR", true),
                Arguments.of(".*", null, ".*", "a", "AND", false),
                // both group and name match
                Arguments.of(".*", "a", ".*", "b", "OR", true),
                Arguments.of(".*", "a", ".*", "b", "AND", true),
                // both group and name doesn't match
                Arguments.of(".*", "a", "b", "c", "OR", true),
                Arguments.of(".*", "a", "b", "c", "AND", false),
                // specific regex for group
                Arguments.of("^us\\.springett$", "us.springett", null, null, "OR", true),
                // specific regex for name
                Arguments.of(null, null, "^dependency-track$", "dependency-track", "OR", true),
                // generalized, case-insensitive regex for group
                Arguments.of("(?i)^(org\\.apache)(\\.[\\w.]+)?$", "Org.Apache.Logging.Log4J", null, "log4j-test", "OR", true),
                // same as above, but with incomplete regex
                Arguments.of("(?i)^(org\\.apache)", "Org.Apache.Logging.Log4J", null, "log4j-test", "OR", false),
                // generalized regex for names
                Arguments.of(null, "org.apache.logging.log4j", "^(log4j-)([\\w-]+)$", "log4j-test", "OR", true),
                // same as above, but with incomplete regex
                Arguments.of(null, "org.apache.logging.log4j", "^(log4j-)", "log4j-test", "OR", false)
        );
    }

    @ParameterizedTest
    @MethodSource("testParameters")
    void testIsInternal(final String groupsRegexProperty,
                        final String componentGroup,
                        final String namesRegexProperty,
                        final String componentName,
                        final String matchMode,
                        final boolean shouldBeInternal) {
        qm.createConfigProperty(
                INTERNAL_COMPONENTS_GROUPS_REGEX.getGroupName(),
                INTERNAL_COMPONENTS_GROUPS_REGEX.getPropertyName(),
                groupsRegexProperty,
                INTERNAL_COMPONENTS_GROUPS_REGEX.getPropertyType(),
                INTERNAL_COMPONENTS_GROUPS_REGEX.getDescription()
        );
        qm.createConfigProperty(
                INTERNAL_COMPONENTS_NAMES_REGEX.getGroupName(),
                INTERNAL_COMPONENTS_NAMES_REGEX.getPropertyName(),
                namesRegexProperty,
                INTERNAL_COMPONENTS_NAMES_REGEX.getPropertyType(),
                INTERNAL_COMPONENTS_NAMES_REGEX.getDescription()
        );
        qm.createConfigProperty(
                INTERNAL_COMPONENTS_MATCH_MODE.getGroupName(),
                INTERNAL_COMPONENTS_MATCH_MODE.getPropertyName(),
                matchMode,
                INTERNAL_COMPONENTS_MATCH_MODE.getPropertyType(),
                INTERNAL_COMPONENTS_MATCH_MODE.getDescription()
        );

        final Component component = new Component();
        component.setGroup(componentGroup);
        component.setName(componentName);

        assertEquals(shouldBeInternal, InternalComponentIdentificationUtil.isInternalComponent(component));
    }

}
