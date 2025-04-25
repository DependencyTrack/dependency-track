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
import static org.junit.jupiter.api.Assertions.assertEquals;

class InternalComponentIdentificationUtilTest extends PersistenceCapableTest {

    public static Collection<Arguments> testParameters() {
        return Arrays.asList(
                // neither regexes nor group / name provided
                Arguments.of("", "", "", "", false),
                // Neither group nor name provided
                Arguments.of(".*", null, ".*", null, false),
                // group matches, name not provided
                Arguments.of(".*", "a", ".*", null, true),
                // group not provided, name matches
                Arguments.of(".*", null, ".*", "a", true),
                // both group and name match
                Arguments.of(".*", "a", ".*", "b", true),
                // specific regex for group
                Arguments.of("^us\\.springett$", "us.springett", null, null, true),
                // specific regex for name
                Arguments.of(null, null, "^dependency-track$", "dependency-track", true),
                // generalized, case-insensitive regex for group
                Arguments.of("(?i)^(org\\.apache)(\\.[\\w.]+)?$", "Org.Apache.Logging.Log4J", null, "log4j-test", true),
                // same as above, but with incomplete regex
                Arguments.of("(?i)^(org\\.apache)", "Org.Apache.Logging.Log4J", null, "log4j-test", false),
                // generalized regex for names
                Arguments.of(null, "org.apache.logging.log4j", "^(log4j-)([\\w-]+)$", "log4j-test", true),
                // same as above, but with incomplete regex
                Arguments.of(null, "org.apache.logging.log4j", "^(log4j-)", "log4j-test", false)
        );
    }

    @ParameterizedTest
    @MethodSource("testParameters")
    void testIsInternal(final String groupsRegexProperty,
                        final String componentGroup,
                        final String namesRegexProperty,
                        final String componentName,
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

        final Component component = new Component();
        component.setGroup(componentGroup);
        component.setName(componentName);

        assertEquals(shouldBeInternal, InternalComponentIdentificationUtil.isInternalComponent(component));
    }

}
