package org.apereo.cas.support.oauth.validator.authorization;

import org.apereo.cas.audit.AuditableExecution;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.OAuth20Constants;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.context.J2EContext;

/**
 * This is {@link OAuth20ProofKeyCodeExchangeResponseTypeAuthorizationRequestValidator}.
 *
 * @author Misagh Moayyed
 * @since 6.0.0
 */
@Slf4j
public class OAuth20ProofKeyCodeExchangeResponseTypeAuthorizationRequestValidator extends OAuth20AuthorizationCodeResponseTypeAuthorizationRequestValidator {

    public OAuth20ProofKeyCodeExchangeResponseTypeAuthorizationRequestValidator(final ServicesManager servicesManager,
                                                                                final ServiceFactory<WebApplicationService> webApplicationServiceServiceFactory,
                                                                                final AuditableExecution registeredServiceAccessStrategyEnforcer) {
        super(servicesManager, webApplicationServiceServiceFactory, registeredServiceAccessStrategyEnforcer);
    }

    @Override
    public boolean supports(final J2EContext context) {
        val challenge = context.getRequestParameter(OAuth20Constants.CODE_VERIFIER);
        return StringUtils.isNotBlank(challenge) && super.supports(context);
    }
}
