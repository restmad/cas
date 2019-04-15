package org.apereo.cas.gauth.token;

import org.apereo.cas.authentication.OneTimeToken;
import org.apereo.cas.otp.repository.token.OneTimeTokenRepository;
import org.apereo.cas.util.SchedulingUtils;

import lombok.Getter;
import lombok.val;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationContext;

import javax.annotation.PostConstruct;

import static org.junit.jupiter.api.Assertions.*;

/**
 * This is {@link BaseOneTimeTokenRepositoryTests}.
 *
 * @author Timur Duehr
 * @since 6.0.0
 */
@Getter
public abstract class BaseOneTimeTokenRepositoryTests {
    public static final String CASUSER = "casuser";

    @Autowired
    @Qualifier("oneTimeTokenAuthenticatorTokenRepository")
    protected OneTimeTokenRepository oneTimeTokenAuthenticatorTokenRepository;

    @Test
    public void verifyTokenSave() {
        var token = (OneTimeToken) new GoogleAuthenticatorToken(1234, CASUSER);
        oneTimeTokenAuthenticatorTokenRepository.store(token);
        assertTrue(oneTimeTokenAuthenticatorTokenRepository.exists(CASUSER, 1234));
        token = oneTimeTokenAuthenticatorTokenRepository.get(CASUSER, 1234);
        assertTrue(token.getId() > 0);
    }

    @Test
    public void verifyTokensWithUniqueIdsSave() {
        val token = new GoogleAuthenticatorToken(1111, CASUSER);
        oneTimeTokenAuthenticatorTokenRepository.store(token);

        val token2 = new GoogleAuthenticatorToken(5678, CASUSER);
        oneTimeTokenAuthenticatorTokenRepository.store(token2);

        val t1 = oneTimeTokenAuthenticatorTokenRepository.get(CASUSER, 1111);
        val t2 = oneTimeTokenAuthenticatorTokenRepository.get(CASUSER, 5678);

        assertTrue(t1.getId() > 0);
        assertTrue(t2.getId() > 0);
        assertNotEquals(token.getId(), token2.getId());
        assertEquals(1111, (int) t1.getToken());
    }

    @Test
    public void verifyRemoveByUserAndCode() {
        val token = new GoogleAuthenticatorToken(1984, CASUSER);
        oneTimeTokenAuthenticatorTokenRepository.store(token);
        var newToken = oneTimeTokenAuthenticatorTokenRepository.get(CASUSER, 1984);
        assertNotNull(newToken);
        assertTrue(newToken.getId() > 0);
        oneTimeTokenAuthenticatorTokenRepository.remove(CASUSER, 1984);
        newToken = oneTimeTokenAuthenticatorTokenRepository.get(CASUSER, 1984);
        assertNull(newToken);
    }

    @Test
    public void verifyRemoveByCode() {
        val token = new GoogleAuthenticatorToken(51984, "someone");
        oneTimeTokenAuthenticatorTokenRepository.store(token);
        var newToken = oneTimeTokenAuthenticatorTokenRepository.get(token.getUserId(), token.getToken());
        assertNotNull(newToken);
        assertTrue(newToken.getId() > 0);
        oneTimeTokenAuthenticatorTokenRepository.remove(token.getToken());
        newToken = oneTimeTokenAuthenticatorTokenRepository.get(token.getUserId(), token.getToken());
        assertNull(newToken);
    }

    @Test
    public void verifySize() {
        assertEquals(oneTimeTokenAuthenticatorTokenRepository.count(), 0);
        val token = new GoogleAuthenticatorToken(916984, "sample");
        oneTimeTokenAuthenticatorTokenRepository.store(token);
        assertEquals(1, oneTimeTokenAuthenticatorTokenRepository.count());
        assertEquals(1, oneTimeTokenAuthenticatorTokenRepository.count("sample"));
        oneTimeTokenAuthenticatorTokenRepository.removeAll();
        assertEquals(0, oneTimeTokenAuthenticatorTokenRepository.count(), "Repository is not empty");
    }

    @TestConfiguration
    public static class BaseTestConfiguration {
        @Autowired
        protected ApplicationContext applicationContext;

        @PostConstruct
        public void init() {
            SchedulingUtils.prepScheduledAnnotationBeanPostProcessor(applicationContext);
        }
    }
}
