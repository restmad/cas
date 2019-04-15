package org.apereo.cas.config;

import org.apereo.cas.audit.AuditTrailRecordResolutionPlan;
import org.apereo.cas.audit.AuditTrailRecordResolutionPlanConfigurer;
import org.apereo.cas.authentication.bypass.audit.MultifactorAuthenticationProviderBypassAuditResourceResolver;
import org.apereo.cas.configuration.CasConfigurationProperties;

import org.apereo.inspektr.audit.spi.support.DefaultAuditActionResolver;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * This is {@link CasCoreMultifactorAuthenticationAuditConfiguration}.
 *
 * @author Travis Schmidt
 * @since 6.0.0
 */
@Configuration("casCoreMultifactorAuthenticationAuditConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class CasCoreMultifactorAuthenticationAuditConfiguration implements AuditTrailRecordResolutionPlanConfigurer {

    @Override
    public void configureAuditTrailRecordResolutionPlan(final AuditTrailRecordResolutionPlan plan) {
        plan.registerAuditResourceResolver("MFA_BYPASS_RESOURCE_RESOLVER", new MultifactorAuthenticationProviderBypassAuditResourceResolver());
        plan.registerAuditActionResolver("MFA_BYPASS_ACTION_RESOLVER", new DefaultAuditActionResolver());
    }
}
