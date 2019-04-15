package org.apereo.cas.uma.web.controllers.claims;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.RegisteredServiceAccessStrategyUtils;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.services.UnauthorizedServiceException;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.ticket.InvalidTicketException;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.uma.ticket.permission.UmaPermissionTicket;
import org.apereo.cas.uma.ticket.permission.UmaPermissionTicketFactory;
import org.apereo.cas.uma.ticket.resource.repository.ResourceSetRepository;
import org.apereo.cas.uma.web.controllers.BaseUmaEndpointController;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This is {@link UmaRequestingPartyClaimsCollectionEndpointController}.
 *
 * @author Misagh Moayyed
 * @since 6.0.0
 */
@Controller("umaRequestingPartyClaimsCollectionEndpointController")
@Slf4j
public class UmaRequestingPartyClaimsCollectionEndpointController extends BaseUmaEndpointController {
    private final ServicesManager servicesManager;
    private final TicketRegistry ticketRegistry;

    public UmaRequestingPartyClaimsCollectionEndpointController(final UmaPermissionTicketFactory umaPermissionTicketFactory,
                                                                final ResourceSetRepository umaResourceSetRepository,
                                                                final CasConfigurationProperties casProperties,
                                                                final ServicesManager servicesManager,
                                                                final TicketRegistry ticketRegistry) {
        super(umaPermissionTicketFactory, umaResourceSetRepository, casProperties);
        this.servicesManager = servicesManager;
        this.ticketRegistry = ticketRegistry;
    }

    /**
     * Gets claims.
     *
     * @param clientId    the client id
     * @param redirectUri the redirect uri
     * @param ticketId    the ticket id
     * @param state       the state
     * @param request     the request
     * @param response    the response
     * @return redirect view
     */
    @GetMapping(value = '/' + OAuth20Constants.BASE_OAUTH20_URL + '/' + OAuth20Constants.UMA_CLAIMS_COLLECTION_URL)
    public View getClaims(@RequestParam("client_id") final String clientId,
                          @RequestParam("redirect_uri") final String redirectUri,
                          @RequestParam("ticket") final String ticketId,
                          @RequestParam(value = "state", required = false) final String state,
                          final HttpServletRequest request, final HttpServletResponse response) {

        val profileResult = getAuthenticatedProfile(request, response, OAuth20Constants.UMA_PROTECTION_SCOPE);

        val service = OAuth20Utils.getRegisteredOAuthServiceByClientId(servicesManager, clientId);
        RegisteredServiceAccessStrategyUtils.ensureServiceAccessIsAllowed(service);

        val ticket = ticketRegistry.getTicket(ticketId, UmaPermissionTicket.class);
        if (ticket == null || ticket.isExpired()) {
            throw new InvalidTicketException(ticketId);
        }

        ticket.getClaims().putAll(profileResult.getAttributes());
        this.ticketRegistry.updateTicket(ticket);

        if (StringUtils.isBlank(redirectUri) || !service.matches(redirectUri)) {
            throw new UnauthorizedServiceException("Redirect URI is unauthorized for this service definition");
        }

        val template = UriComponentsBuilder.fromUriString(redirectUri);
        template.queryParam(OAuth20Constants.AUTHORIZATION_STATE, OAuth20Constants.CLAIMS_SUBMITTED);
        if (StringUtils.isNotBlank(state)) {
            template.queryParam(OAuth20Constants.STATE, state);
        }

        val redirectTo = template.toUriString();
        return new RedirectView(redirectTo);
    }
}
