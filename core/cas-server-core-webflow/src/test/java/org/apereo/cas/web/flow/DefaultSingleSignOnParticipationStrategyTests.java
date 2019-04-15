package org.apereo.cas.web.flow;

import org.apereo.cas.CasProtocolConstants;
import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.ticket.registry.TicketRegistrySupport;
import org.apereo.cas.web.support.WebUtils;

import lombok.val;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.webflow.context.servlet.ServletExternalContext;
import org.springframework.webflow.test.MockRequestContext;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link DefaultSingleSignOnParticipationStrategyTests}.
 *
 * @author Misagh Moayyed
 * @since 6.1.0
 */
public class DefaultSingleSignOnParticipationStrategyTests {
    @Test
    public void verifyParticipatesForRenew() {
        val mgr = mock(ServicesManager.class);
        val context = new MockRequestContext();
        val request = new MockHttpServletRequest();
        val response = new MockHttpServletResponse();

        val strategy = new DefaultSingleSignOnParticipationStrategy(mgr, true, true, mock(TicketRegistrySupport.class));
        context.setExternalContext(new ServletExternalContext(new MockServletContext(), request, response));
        request.addParameter(CasProtocolConstants.PARAMETER_RENEW, "true");
        assertTrue(strategy.isParticipating(context) || strategy.isCreateCookieOnRenewedAuthentication(context));
    }

    @Test
    public void verifyParticipatesForRenewDisabled() {
        val mgr = mock(ServicesManager.class);
        val context = new MockRequestContext();
        val request = new MockHttpServletRequest();
        val response = new MockHttpServletResponse();

        val strategy = new DefaultSingleSignOnParticipationStrategy(mgr, false, true, mock(TicketRegistrySupport.class));
        context.setExternalContext(new ServletExternalContext(new MockServletContext(), request, response));
        request.addParameter(CasProtocolConstants.PARAMETER_RENEW, "true");
        assertFalse(strategy.isParticipating(context));
    }

    @Test
    public void verifyDoesNotParticipateForService() {
        val mgr = mock(ServicesManager.class);
        val registeredService = CoreAuthenticationTestUtils.getRegisteredService();
        when(registeredService.getAccessStrategy().isServiceAccessAllowedForSso()).thenReturn(false);
        when(mgr.findServiceBy(any(Service.class))).thenReturn(registeredService);

        val context = new MockRequestContext();
        val request = new MockHttpServletRequest();
        val response = new MockHttpServletResponse();

        val strategy = new DefaultSingleSignOnParticipationStrategy(mgr, false, true, mock(TicketRegistrySupport.class));
        context.setExternalContext(new ServletExternalContext(new MockServletContext(), request, response));

        WebUtils.putServiceIntoFlowScope(context, CoreAuthenticationTestUtils.getWebApplicationService());
        WebUtils.putAuthentication(CoreAuthenticationTestUtils.getAuthentication("casuser"), context);

        assertFalse(strategy.isParticipating(context));
    }
}
