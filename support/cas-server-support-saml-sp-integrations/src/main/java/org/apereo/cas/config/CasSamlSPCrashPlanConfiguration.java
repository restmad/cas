package org.apereo.cas.config;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.support.saml.sps.AbstractSamlSPProperties;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * This is {@link CasSamlSPCrashPlanConfiguration}.
 *
 * @author Misagh Moayyed
 * @since 6.1.0
 */
@Configuration("casSamlSPCrashPlanConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class CasSamlSPCrashPlanConfiguration extends BaseCasSamlSPConfiguration {

    @Override
    protected AbstractSamlSPProperties getServiceProvider() {
        return casProperties.getSamlSp().getCrashPlan();
    }
}
