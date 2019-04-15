package org.apereo.cas.authentication.trigger;

import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.MultifactorAuthenticationProvider;
import org.apereo.cas.authentication.MultifactorAuthenticationProviderResolver;
import org.apereo.cas.authentication.MultifactorAuthenticationTrigger;
import org.apereo.cas.authentication.MultifactorAuthenticationUtils;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.spring.ApplicationContextProvider;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.Ordered;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

import static org.springframework.util.StringUtils.commaDelimitedListToSet;

/**
 * This is {@link AuthenticationAttributeMultifactorAuthenticationTrigger}.
 *
 * @author Misagh Moayyed
 * @since 6.0.0
 */
@Setter
@Getter
@Slf4j
@RequiredArgsConstructor
public class AuthenticationAttributeMultifactorAuthenticationTrigger implements MultifactorAuthenticationTrigger {
    private final CasConfigurationProperties casProperties;
    private final MultifactorAuthenticationProviderResolver multifactorAuthenticationProviderResolver;

    private int order = Ordered.LOWEST_PRECEDENCE;

    @Override
    public Optional<MultifactorAuthenticationProvider> isActivated(final Authentication authentication, final RegisteredService registeredService,
                                                                   final HttpServletRequest httpServletRequest, final Service service) {

        val globalAuthenticationAttributeValueRegex = casProperties.getAuthn().getMfa().getGlobalAuthenticationAttributeValueRegex();
        val attributeNames = commaDelimitedListToSet(casProperties.getAuthn().getMfa().getGlobalAuthenticationAttributeNameTriggers());

        if (authentication == null) {
            LOGGER.debug("No authentication is available to determine event for principal");
            return Optional.empty();
        }

        if (attributeNames.isEmpty()) {
            LOGGER.trace("Authentication attribute name to determine event is not configured");
            return Optional.empty();
        }

        val applicationContext = ApplicationContextProvider.getApplicationContext();
        val providerMap = MultifactorAuthenticationUtils.getAvailableMultifactorAuthenticationProviders(applicationContext);
        if (providerMap.isEmpty()) {
            LOGGER.error("No multifactor authentication providers are available in the application context");
            return Optional.empty();
        }

        val providers = providerMap.values();
        if (providers.size() == 1 && StringUtils.isNotBlank(globalAuthenticationAttributeValueRegex)) {
            val provider = providers.iterator().next();
            LOGGER.debug("Found a single multifactor provider [{}] in the application context", provider);
            val result = multifactorAuthenticationProviderResolver.resolveEventViaAuthenticationAttribute(authentication, attributeNames, registeredService, Optional.empty(), providers,
                input -> input != null && input.matches(globalAuthenticationAttributeValueRegex));
            if (result != null && !result.isEmpty()) {
                return Optional.of(provider);
            }
        }

        val result = multifactorAuthenticationProviderResolver.resolveEventViaAuthenticationAttribute(authentication, attributeNames, registeredService, Optional.empty(), providers,
            input -> providers.stream().anyMatch(provider -> input != null && provider.matches(input)));
        if (result != null && !result.isEmpty()) {
            val id = CollectionUtils.firstElement(result);
            return MultifactorAuthenticationUtils.getMultifactorAuthenticationProviderById(id.toString(), applicationContext);
        }
        return Optional.empty();
    }
}
