package org.apereo.cas.aup;

import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.configuration.model.support.aup.AcceptableUsagePolicyProperties;
import org.apereo.cas.ticket.registry.TicketRegistrySupport;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.web.support.WebUtils;

import lombok.Getter;
import lombok.val;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.webflow.context.servlet.ServletExternalContext;
import org.springframework.webflow.test.MockRequestContext;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link DefaultAcceptableUsagePolicyRepositoryTests}.
 *
 * @author Misagh Moayyed
 * @since 5.3.0
 */
@Getter
public class DefaultAcceptableUsagePolicyRepositoryTests extends BaseAcceptableUsagePolicyRepositoryTests {

    @Autowired
    @Qualifier("acceptableUsagePolicyRepository")
    protected AcceptableUsagePolicyRepository acceptableUsagePolicyRepository;

    @Test
    public void verifyActionDefaultGlobal() {
        val properties = new AcceptableUsagePolicyProperties();
        properties.setScope(AcceptableUsagePolicyProperties.Scope.GLOBAL);
        verifyAction(properties);
    }

    @Test
    public void verifyActionDefaultAuthentication() {
        val properties = new AcceptableUsagePolicyProperties();
        properties.setScope(AcceptableUsagePolicyProperties.Scope.AUTHENTICATION);
        verifyAction(properties);
    }

    private static void verifyAction(final AcceptableUsagePolicyProperties properties) {
        val context = new MockRequestContext();
        val request = new MockHttpServletRequest();
        context.setExternalContext(new ServletExternalContext(new MockServletContext(), request, new MockHttpServletResponse()));

        val support = mock(TicketRegistrySupport.class);
        when(support.getAuthenticatedPrincipalFrom(anyString()))
            .thenReturn(CoreAuthenticationTestUtils.getPrincipal(CollectionUtils.wrap("carLicense", "false")));
        val repo = new DefaultAcceptableUsagePolicyRepository(support, properties);

        WebUtils.putAuthentication(CoreAuthenticationTestUtils.getAuthentication(), context);
        WebUtils.putTicketGrantingTicketInScopes(context, "TGT-12345");

        val c = CoreAuthenticationTestUtils.getCredentialsWithSameUsernameAndPassword("casaup");
        assertFalse(repo.verify(context, c).isAccepted());
        assertTrue(repo.submit(context, c));
        assertTrue(repo.verify(context, c).isAccepted());
    }

    @Override
    public boolean hasLiveUpdates() {
        return true;
    }
}
