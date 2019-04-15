package org.apereo.cas.util;

import lombok.val;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link RegexUtils}
 *
 * @author David Rodriguez
 * @since 5.1.0
 */
public class RegexUtilsTests {

    @Test
    public void verifyNotValidRegex() {
        val notValidRegex = "***";

        assertFalse(RegexUtils.isValidRegex(notValidRegex));
    }

    @Test
    public void verifyNullRegex() {
        assertFalse(RegexUtils.isValidRegex(null));
    }
}
