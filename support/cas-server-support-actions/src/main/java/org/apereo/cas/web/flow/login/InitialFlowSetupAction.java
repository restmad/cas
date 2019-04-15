package org.apereo.cas.web.flow.login;

import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;
import org.apereo.cas.authentication.AuthenticationServiceSelectionPlan;
import org.apereo.cas.authentication.credential.UsernamePasswordCredential;
import org.apereo.cas.authentication.principal.NullPrincipal;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.RegisteredServiceAccessStrategyUtils;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.services.UnauthorizedServiceException;
import org.apereo.cas.ticket.registry.TicketRegistrySupport;
import org.apereo.cas.web.cookie.CasCookieBuilder;
import org.apereo.cas.web.flow.SingleSignOnParticipationStrategy;
import org.apereo.cas.web.support.ArgumentExtractor;
import org.apereo.cas.web.support.WebUtils;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpMethod;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.execution.repository.NoSuchFlowExecutionException;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Class to automatically set the paths for the CookieGenerators.
 * <p>
 * Note: This is technically not threadsafe, but because its overriding with a
 * constant value it doesn't matter.
 * <p>
 * Note: As of CAS 3.1, this is a required class that retrieves and exposes the
 * values in the two cookies for subclasses to use.
 *
 * @author Scott Battaglia
 * @since 3.1
 */
@Slf4j
@RequiredArgsConstructor
public class InitialFlowSetupAction extends AbstractAction {

    private final List<ArgumentExtractor> argumentExtractors;

    @Getter
    private final ServicesManager servicesManager;

    private final AuthenticationServiceSelectionPlan authenticationRequestServiceSelectionStrategies;
    private final CasCookieBuilder ticketGrantingTicketCookieGenerator;
    private final CasCookieBuilder warnCookieGenerator;
    private final CasConfigurationProperties casProperties;
    private final AuthenticationEventExecutionPlan authenticationEventExecutionPlan;
    private final SingleSignOnParticipationStrategy renewalStrategy;
    private final TicketRegistrySupport ticketRegistrySupport;

    @Override
    public Event doExecute(final RequestContext context) {
        configureCookieGenerators(context);
        configureWebflowContext(context);
        configureWebflowContextForService(context);
        return success();
    }

    private void configureWebflowContextForService(final RequestContext context) {
        val request = WebUtils.getHttpServletRequestFromExternalWebflowContext(context);

        if (request.getMethod().equalsIgnoreCase(HttpMethod.POST.name())) {
            WebUtils.putInitialHttpRequestPostParameters(context);
        }
        WebUtils.putCustomLoginFormFields(context, casProperties.getView().getCustomLoginFormFields());

        val service = WebUtils.getService(this.argumentExtractors, context);
        if (service != null) {
            LOGGER.debug("Placing service in context scope: [{}]", service.getId());

            val selectedService = authenticationRequestServiceSelectionStrategies.resolveService(service);
            val registeredService = this.servicesManager.findServiceBy(selectedService);
            RegisteredServiceAccessStrategyUtils.ensureServiceAccessIsAllowed(registeredService);
            if (registeredService != null && registeredService.getAccessStrategy().isServiceAccessAllowed()) {
                LOGGER.debug("Placing registered service [{}] with id [{}] in context scope",
                    registeredService.getServiceId(),
                    registeredService.getId());
                WebUtils.putRegisteredService(context, registeredService);

                val accessStrategy = registeredService.getAccessStrategy();
                if (accessStrategy.getUnauthorizedRedirectUrl() != null) {
                    LOGGER.debug("Placing registered service's unauthorized redirect url [{}] with id [{}] in context scope",
                        accessStrategy.getUnauthorizedRedirectUrl(),
                        registeredService.getServiceId());
                    WebUtils.putUnauthorizedRedirectUrlIntoFlowScope(context, accessStrategy.getUnauthorizedRedirectUrl());
                }
            }
        } else if (!casProperties.getSso().isAllowMissingServiceParameter()) {
            LOGGER.warn("No service authentication request is available at [{}]. CAS is configured to disable the flow.",
                request.getRequestURL());
            throw new NoSuchFlowExecutionException(context.getFlowExecutionContext().getKey(),
                new UnauthorizedServiceException("screen.service.required.message", "Service is required"));
        }
        WebUtils.putServiceIntoFlowScope(context, service);

        val ticketGrantingTicketId = this.ticketGrantingTicketCookieGenerator.retrieveCookieValue(request);
        WebUtils.putTicketGrantingTicketInScopes(context, ticketGrantingTicketId);
        
        val ssoParticipation = this.renewalStrategy.supports(context) && this.renewalStrategy.isParticipating(context);
        if (!ssoParticipation && StringUtils.isNotBlank(ticketGrantingTicketId)) {
            val auth = this.ticketRegistrySupport.getAuthenticationFrom(ticketGrantingTicketId);
            if (auth != null) {
                WebUtils.putExistingSingleSignOnSessionAvailable(context, true);
                WebUtils.putExistingSingleSignOnSessionPrincipal(context, auth.getPrincipal());
            } else {
                WebUtils.putExistingSingleSignOnSessionAvailable(context, false);
                WebUtils.putExistingSingleSignOnSessionPrincipal(context, NullPrincipal.getInstance());
            }
        }
    }

    private void configureWebflowContext(final RequestContext context) {
        val request = WebUtils.getHttpServletRequestFromExternalWebflowContext(context);
        WebUtils.putWarningCookie(context, Boolean.valueOf(this.warnCookieGenerator.retrieveCookieValue(request)));

        WebUtils.putGoogleAnalyticsTrackingIdIntoFlowScope(context, casProperties.getGoogleAnalytics().getGoogleAnalyticsTrackingId());
        WebUtils.putGeoLocationTrackingIntoFlowScope(context, casProperties.getEvents().isTrackGeolocation());
        WebUtils.putPasswordManagementEnabled(context, casProperties.getAuthn().getPm().isEnabled());
        WebUtils.putRememberMeAuthenticationEnabled(context, casProperties.getTicket().getTgt().getRememberMe().isEnabled());
        WebUtils.putStaticAuthenticationIntoFlowScope(context,
            StringUtils.isNotBlank(casProperties.getAuthn().getAccept().getUsers())
                || StringUtils.isNotBlank(casProperties.getAuthn().getReject().getUsers()));

        if (casProperties.getAuthn().getPolicy().isSourceSelectionEnabled()) {
            val availableHandlers = authenticationEventExecutionPlan.getAuthenticationHandlers()
                .stream()
                .filter(h -> h.supports(UsernamePasswordCredential.class))
                .map(h -> StringUtils.capitalize(h.getName().trim()))
                .distinct()
                .sorted()
                .collect(Collectors.toList());
            WebUtils.putAvailableAuthenticationHandleNames(context, availableHandlers);
        }
    }

    private void configureCookieGenerators(final RequestContext context) {
        val contextPath = context.getExternalContext().getContextPath();
        val cookiePath = StringUtils.isNotBlank(contextPath) ? contextPath + '/' : "/";

        if (casProperties.getWarningCookie().isAutoConfigureCookiePath()) {
            val path = this.warnCookieGenerator.getCookiePath();
            if (StringUtils.isBlank(path)) {
                LOGGER.debug("Setting path for cookies for warn cookie generator to: [{}]", cookiePath);
                this.warnCookieGenerator.setCookiePath(cookiePath);
            } else {
                LOGGER.trace("Warning cookie domain is set to [{}] with path [{}]", this.warnCookieGenerator.getCookieDomain(), path);
            }
        }

        if (casProperties.getTgc().isAutoConfigureCookiePath()) {
            val path = this.ticketGrantingTicketCookieGenerator.getCookiePath();
            if (StringUtils.isBlank(path)) {
                LOGGER.debug("Setting path for cookies for TGC cookie generator to: [{}]", cookiePath);
                this.ticketGrantingTicketCookieGenerator.setCookiePath(cookiePath);
            } else {
                LOGGER.trace("TGC cookie domain is [{}] with path [{}]", this.ticketGrantingTicketCookieGenerator.getCookieDomain(), path);
            }
        }
    }
}
