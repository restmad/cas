package org.apereo.cas.oidc.config;

import org.apereo.cas.ComponentSerializationPlan;
import org.apereo.cas.ComponentSerializationPlanConfigurator;
import org.apereo.cas.authentication.principal.OidcPairwisePersistentIdGenerator;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.oidc.claims.OidcAddressScopeAttributeReleasePolicy;
import org.apereo.cas.oidc.claims.OidcCustomScopeAttributeReleasePolicy;
import org.apereo.cas.oidc.claims.OidcEmailScopeAttributeReleasePolicy;
import org.apereo.cas.oidc.claims.OidcPhoneScopeAttributeReleasePolicy;
import org.apereo.cas.oidc.claims.OidcProfileScopeAttributeReleasePolicy;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.PairwiseOidcRegisteredServiceUsernameAttributeProvider;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * This is {@link OidcComponentSerializationConfiguration}.
 *
 * @author Misagh Moayyed
 * @since 6.1.0
 */
@Configuration("oidcComponentSerializationConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class OidcComponentSerializationConfiguration implements ComponentSerializationPlanConfigurator {

    @Override
    public void configureComponentSerializationPlan(final ComponentSerializationPlan plan) {
        plan.registerSerializableClass(PairwiseOidcRegisteredServiceUsernameAttributeProvider.class);
        plan.registerSerializableClass(OidcRegisteredService.class);
        plan.registerSerializableClass(OidcPairwisePersistentIdGenerator.class);

        plan.registerSerializableClass(OidcAddressScopeAttributeReleasePolicy.class);
        plan.registerSerializableClass(OidcCustomScopeAttributeReleasePolicy.class);
        plan.registerSerializableClass(OidcEmailScopeAttributeReleasePolicy.class);
        plan.registerSerializableClass(OidcPhoneScopeAttributeReleasePolicy.class);
        plan.registerSerializableClass(OidcProfileScopeAttributeReleasePolicy.class);
    }
}
