package org.apereo.cas.authentication.support.password;

import org.apereo.cas.DefaultMessageDescriptor;

import lombok.val;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

/**
 * This is {@link DefaultPasswordPolicyHandlingStrategyTests}.
 *
 * @author Misagh Moayyed
 * @since 6.1.0
 */
public class DefaultPasswordPolicyHandlingStrategyTests {

    @Test
    public void verifyOperation() throws Exception {
        val s = new DefaultPasswordPolicyHandlingStrategy<Object>();
        assertTrue(s.handle(new Object(), null).isEmpty());
        val cfg = new PasswordPolicyConfiguration(30);
        cfg.setAccountStateHandler((o, o2) -> Collections.singletonList(new DefaultMessageDescriptor("bad.password")));
        assertFalse(s.handle(new Object(), cfg).isEmpty());
    }
}
