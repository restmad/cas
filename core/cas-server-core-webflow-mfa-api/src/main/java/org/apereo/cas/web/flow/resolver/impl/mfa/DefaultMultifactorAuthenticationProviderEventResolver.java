package org.apereo.cas.web.flow.resolver.impl.mfa;

import org.apereo.cas.authentication.MultifactorAuthenticationTrigger;
import org.apereo.cas.authentication.MultifactorAuthenticationUtils;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.web.flow.authentication.BaseMultifactorAuthenticationProviderEventResolver;
import org.apereo.cas.web.flow.resolver.impl.CasWebflowEventResolutionConfigurationContext;
import org.apereo.cas.web.support.WebUtils;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.inspektr.audit.annotation.Audit;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.util.Optional;
import java.util.Set;

/**
 * This is {@link DefaultMultifactorAuthenticationProviderEventResolver}.
 *
 * @author Misagh Moayyed
 * @since 6.0.0
 */
@Slf4j
public class DefaultMultifactorAuthenticationProviderEventResolver extends BaseMultifactorAuthenticationProviderEventResolver {
    private final MultifactorAuthenticationTrigger multifactorAuthenticationTrigger;

    public DefaultMultifactorAuthenticationProviderEventResolver(final CasWebflowEventResolutionConfigurationContext webflowEventResolutionConfigurationContext,
                                                                 final MultifactorAuthenticationTrigger multifactorAuthenticationTrigger) {
        super(webflowEventResolutionConfigurationContext);
        this.multifactorAuthenticationTrigger = multifactorAuthenticationTrigger;
    }

    @Override
    public Set<Event> resolveInternal(final RequestContext context) {
        val registeredService = resolveRegisteredServiceInRequestContext(context);
        val service = resolveServiceFromAuthenticationRequest(context);
        val authentication = WebUtils.getAuthentication(context);
        val request = WebUtils.getHttpServletRequestFromExternalWebflowContext(context);

        val result = multifactorAuthenticationTrigger.isActivated(authentication, registeredService, request, service);
        return result.map(provider -> {
            LOGGER.trace("Attempting to build an event based on the authentication provider [{}] and service [{}]", provider, registeredService);
            val event = MultifactorAuthenticationUtils.validateEventIdForMatchingTransitionInContext(provider.getId(), Optional.of(context),
                MultifactorAuthenticationUtils.buildEventAttributeMap(authentication.getPrincipal(), Optional.ofNullable(registeredService), provider));
            return CollectionUtils.wrapSet(event);
        }).orElse(null);
    }

    @Audit(action = "AUTHENTICATION_EVENT",
        actionResolverName = "AUTHENTICATION_EVENT_ACTION_RESOLVER",
        resourceResolverName = "AUTHENTICATION_EVENT_RESOURCE_RESOLVER")
    @Override
    public Event resolveSingle(final RequestContext context) {
        return super.resolveSingle(context);
    }
}
