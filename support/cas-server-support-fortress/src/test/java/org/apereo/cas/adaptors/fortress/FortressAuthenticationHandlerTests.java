package org.apereo.cas.adaptors.fortress;

import org.apereo.cas.authentication.CoreAuthenticationTestUtils;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.directory.fortress.core.AccessMgr;
import org.apache.directory.fortress.core.GlobalErrIds;
import org.apache.directory.fortress.core.PasswordException;
import org.apache.directory.fortress.core.model.Session;
import org.apache.directory.fortress.core.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import javax.security.auth.login.FailedLoginException;
import javax.xml.bind.JAXBContext;
import java.io.StringWriter;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * This is {@link FortressAuthenticationHandler}.
 *
 * @author yudhi.k.surtan
 * @since 5.2.0
 */
@Slf4j
public class FortressAuthenticationHandlerTests {
    @Mock
    private AccessMgr accessManager;

    @InjectMocks
    private FortressAuthenticationHandler fortressAuthenticationHandler;

    @BeforeEach
    public void initializeTest() {
        MockitoAnnotations.initMocks(this);
        fortressAuthenticationHandler.setAccessManager(accessManager);
    }

    @Test
    public void verifyUnauthorizedUserLoginIncorrect() throws Exception {
        Mockito.when(accessManager.createSession(ArgumentMatchers.any(User.class), ArgumentMatchers.anyBoolean()))
            .thenThrow(new PasswordException(GlobalErrIds.USER_PW_INVLD, "error message"));
        assertThrows(FailedLoginException.class,
            () -> fortressAuthenticationHandler.authenticateUsernamePasswordInternal(
                CoreAuthenticationTestUtils.getCredentialsWithSameUsernameAndPassword(), null));
    }

    @Test
    @SneakyThrows
    public void verifyAuthenticateSuccessfully() {
        val sessionId = UUID.randomUUID();
        val session = new Session(new User(CoreAuthenticationTestUtils.CONST_USERNAME), sessionId.toString());
        session.setAuthenticated(true);
        Mockito.when(accessManager.createSession(ArgumentMatchers.any(User.class), ArgumentMatchers.anyBoolean())).thenReturn(session);
        val handlerResult = fortressAuthenticationHandler.authenticateUsernamePasswordInternal(
            CoreAuthenticationTestUtils.getCredentialsWithSameUsernameAndPassword(), null);
        assertEquals(CoreAuthenticationTestUtils.CONST_USERNAME,
            handlerResult.getPrincipal().getId());
        val jaxbContext = JAXBContext.newInstance(Session.class);
        val marshaller = jaxbContext.createMarshaller();
        val writer = new StringWriter();
        marshaller.marshal(session, writer);
        assertEquals(writer.toString(), handlerResult.getPrincipal()
            .getAttributes().get(FortressAuthenticationHandler.FORTRESS_SESSION_KEY).get(0));
    }
}
