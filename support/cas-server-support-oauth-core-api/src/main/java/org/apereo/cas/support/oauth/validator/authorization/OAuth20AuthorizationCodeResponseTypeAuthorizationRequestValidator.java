package org.apereo.cas.support.oauth.validator.authorization;

import org.apereo.cas.audit.AuditableContext;
import org.apereo.cas.audit.AuditableExecution;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.util.HttpRequestUtils;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.pac4j.core.context.J2EContext;
import org.springframework.core.Ordered;

import java.util.stream.Stream;

/**
 * This is {@link OAuth20AuthorizationCodeResponseTypeAuthorizationRequestValidator}.
 *
 * @author Misagh Moayyed
 * @since 5.2.0
 */
@Slf4j
@RequiredArgsConstructor
@Getter
@Setter
public class OAuth20AuthorizationCodeResponseTypeAuthorizationRequestValidator implements OAuth20AuthorizationRequestValidator {
    /**
     * Service manager.
     */
    protected final ServicesManager servicesManager;
    /**
     * Service factory.
     */
    protected final ServiceFactory<WebApplicationService> webApplicationServiceServiceFactory;
    /**
     * Service access enforcer.
     */
    protected final AuditableExecution registeredServiceAccessStrategyEnforcer;

    private int order = Ordered.LOWEST_PRECEDENCE;

    @Override
    public boolean validate(final J2EContext context) {
        val request = context.getRequest();
        val checkParameterExist = Stream.of(OAuth20Constants.CLIENT_ID, OAuth20Constants.REDIRECT_URI, OAuth20Constants.RESPONSE_TYPE)
            .allMatch(s -> HttpRequestUtils.doesParameterExist(request, s));

        if (!checkParameterExist) {
            LOGGER.warn("Missing required parameters (client id, redirect uri, etc) for response type [{}].", getResponseType());
            return false;
        }

        val responseType = request.getParameter(OAuth20Constants.RESPONSE_TYPE);
        if (!OAuth20Utils.checkResponseTypes(responseType, OAuth20ResponseTypes.values())) {
            LOGGER.warn("Response type [{}] is not supported.", responseType);
            return false;
        }

        val clientId = request.getParameter(OAuth20Constants.CLIENT_ID);
        val registeredService = getRegisteredServiceByClientId(clientId);
        val service = registeredService != null ? webApplicationServiceServiceFactory.createService(registeredService.getServiceId()) : null;
        val audit = AuditableContext.builder()
            .service(service)
            .registeredService(registeredService)
            .build();
        val accessResult = this.registeredServiceAccessStrategyEnforcer.execute(audit);

        if (accessResult.isExecutionFailure()) {
            LOGGER.warn("Registered service [{}] is not found or is not authorized for access.", registeredService);
            return false;
        }

        val redirectUri = request.getParameter(OAuth20Constants.REDIRECT_URI);
        if (!OAuth20Utils.checkCallbackValid(registeredService, redirectUri)) {
            LOGGER.warn("Callback URL [{}] is not authorized for registered service [{}].", redirectUri, registeredService);
            return false;
        }

        return OAuth20Utils.isAuthorizedResponseTypeForService(context, registeredService);
    }

    /**
     * Gets registered service by client id.
     *
     * @param clientId the client id
     * @return the registered service by client id
     */
    protected OAuthRegisteredService getRegisteredServiceByClientId(final String clientId) {
        return OAuth20Utils.getRegisteredOAuthServiceByClientId(this.servicesManager, clientId);
    }

    @Override
    public boolean supports(final J2EContext context) {
        val grantType = context.getRequestParameter(OAuth20Constants.RESPONSE_TYPE);
        return OAuth20Utils.isResponseType(grantType, getResponseType());
    }

    /**
     * Gets response type.
     *
     * @return the response type
     */
    public OAuth20ResponseTypes getResponseType() {
        return OAuth20ResponseTypes.CODE;
    }
}
