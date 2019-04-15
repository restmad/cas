package org.apereo.cas.adaptors.trusted.config;

import org.apereo.cas.adaptors.trusted.authentication.handler.support.PrincipalBearingCredentialsAuthenticationHandler;
import org.apereo.cas.adaptors.trusted.authentication.principal.PrincipalBearingPrincipalResolver;
import org.apereo.cas.adaptors.trusted.authentication.principal.RemoteRequestPrincipalAttributesExtractor;
import org.apereo.cas.adaptors.trusted.authentication.principal.ShibbolethServiceProviderRequestPrincipalAttributesExtractor;
import org.apereo.cas.adaptors.trusted.web.flow.BasePrincipalFromNonInteractiveCredentialsAction;
import org.apereo.cas.adaptors.trusted.web.flow.ChainingPrincipalFromRequestNonInteractiveCredentialsAction;
import org.apereo.cas.adaptors.trusted.web.flow.PrincipalFromRequestHeaderNonInteractiveCredentialsAction;
import org.apereo.cas.adaptors.trusted.web.flow.PrincipalFromRequestRemoteUserNonInteractiveCredentialsAction;
import org.apereo.cas.adaptors.trusted.web.flow.PrincipalFromRequestUserPrincipalNonInteractiveCredentialsAction;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.adaptive.AdaptiveAuthenticationPolicy;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalFactoryUtils;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.authentication.principal.resolvers.ChainingPrincipalResolver;
import org.apereo.cas.authentication.principal.resolvers.EchoingPrincipalResolver;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.web.flow.resolver.CasDelegatingWebflowEventResolver;
import org.apereo.cas.web.flow.resolver.CasWebflowEventResolver;

import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apereo.services.persondir.IPersonAttributeDao;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.webflow.execution.Action;

/**
 * This is {@link TrustedAuthenticationConfiguration}.
 *
 * @author Misagh Moayyed
 * @author Dmitriy Kopylenko
 * @since 5.0.0
 */
@Configuration("trustedAuthenticationConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class TrustedAuthenticationConfiguration {

    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("adaptiveAuthenticationPolicy")
    private ObjectProvider<AdaptiveAuthenticationPolicy> adaptiveAuthenticationPolicy;

    @Autowired
    @Qualifier("serviceTicketRequestWebflowEventResolver")
    private ObjectProvider<CasWebflowEventResolver> serviceTicketRequestWebflowEventResolver;

    @Autowired
    @Qualifier("initialAuthenticationAttemptWebflowEventResolver")
    private ObjectProvider<CasDelegatingWebflowEventResolver> initialAuthenticationAttemptWebflowEventResolver;

    @Autowired
    @Qualifier("servicesManager")
    private ObjectProvider<ServicesManager> servicesManager;

    @Autowired
    @Qualifier("attributeRepository")
    private ObjectProvider<IPersonAttributeDao> attributeRepository;

    @Bean
    @RefreshScope
    public AuthenticationHandler principalBearingCredentialsAuthenticationHandler() {
        val trusted = casProperties.getAuthn().getTrusted();
        return new PrincipalBearingCredentialsAuthenticationHandler(trusted.getName(),
            servicesManager.getIfAvailable(), trustedPrincipalFactory(),
            trusted.getOrder());
    }

    @Bean
    @RefreshScope
    public PrincipalResolver trustedPrincipalResolver() {
        val resolver = new ChainingPrincipalResolver();
        val personDirectory = casProperties.getPersonDirectory();
        val trusted = casProperties.getAuthn().getTrusted();
        val principalAttribute = StringUtils.defaultIfBlank(trusted.getPrincipalAttribute(), personDirectory.getPrincipalAttribute());
        val bearingPrincipalResolver = new PrincipalBearingPrincipalResolver(attributeRepository.getIfAvailable(),
            trustedPrincipalFactory(),
            trusted.isReturnNull() || personDirectory.isReturnNull(),
            principalAttribute,
            trusted.isUseExistingPrincipalId() || personDirectory.isUseExistingPrincipalId(),
            trusted.isAttributeResolutionEnabled(),
            org.springframework.util.StringUtils.commaDelimitedListToSet(trusted.getActiveAttributeRepositoryIds()));
        resolver.setChain(CollectionUtils.wrapList(new EchoingPrincipalResolver(), bearingPrincipalResolver));
        return resolver;
    }

    @ConditionalOnMissingBean(name = "trustedPrincipalFactory")
    @Bean
    public PrincipalFactory trustedPrincipalFactory() {
        return PrincipalFactoryUtils.newPrincipalFactory();
    }

    @ConditionalOnMissingBean(name = "remoteRequestPrincipalAttributesExtractor")
    @Bean
    public RemoteRequestPrincipalAttributesExtractor remoteRequestPrincipalAttributesExtractor() {
        return new ShibbolethServiceProviderRequestPrincipalAttributesExtractor();
    }

    @Bean
    public BasePrincipalFromNonInteractiveCredentialsAction principalFromRemoteUserAction() {
        return new PrincipalFromRequestRemoteUserNonInteractiveCredentialsAction(
            initialAuthenticationAttemptWebflowEventResolver.getIfAvailable(),
            serviceTicketRequestWebflowEventResolver.getIfAvailable(),
            adaptiveAuthenticationPolicy.getIfAvailable(),
            trustedPrincipalFactory(),
            remoteRequestPrincipalAttributesExtractor());
    }

    @Bean
    public BasePrincipalFromNonInteractiveCredentialsAction principalFromRemoteUserPrincipalAction() {
        return new PrincipalFromRequestUserPrincipalNonInteractiveCredentialsAction(
            initialAuthenticationAttemptWebflowEventResolver.getIfAvailable(),
            serviceTicketRequestWebflowEventResolver.getIfAvailable(),
            adaptiveAuthenticationPolicy.getIfAvailable(),
            trustedPrincipalFactory(),
            remoteRequestPrincipalAttributesExtractor());
    }

    @Bean
    public BasePrincipalFromNonInteractiveCredentialsAction principalFromRemoteHeaderPrincipalAction() {
        val trusted = casProperties.getAuthn().getTrusted();
        return new PrincipalFromRequestHeaderNonInteractiveCredentialsAction(
            initialAuthenticationAttemptWebflowEventResolver.getIfAvailable(),
            serviceTicketRequestWebflowEventResolver.getIfAvailable(),
            adaptiveAuthenticationPolicy.getIfAvailable(),
            trustedPrincipalFactory(),
            remoteRequestPrincipalAttributesExtractor(),
            trusted.getRemotePrincipalHeader());
    }

    @ConditionalOnMissingBean(name = "remoteUserAuthenticationAction")
    @Bean
    public Action remoteUserAuthenticationAction() {
        val chain =
            new ChainingPrincipalFromRequestNonInteractiveCredentialsAction(
                initialAuthenticationAttemptWebflowEventResolver.getIfAvailable(),
                serviceTicketRequestWebflowEventResolver.getIfAvailable(),
                adaptiveAuthenticationPolicy.getIfAvailable(),
                trustedPrincipalFactory(),
                remoteRequestPrincipalAttributesExtractor());
        chain.addAction(principalFromRemoteUserAction());
        chain.addAction(principalFromRemoteUserPrincipalAction());
        chain.addAction(principalFromRemoteHeaderPrincipalAction());
        return chain;
    }

    @ConditionalOnMissingBean(name = "trustedAuthenticationEventExecutionPlanConfigurer")
    @Bean
    public AuthenticationEventExecutionPlanConfigurer trustedAuthenticationEventExecutionPlanConfigurer() {
        return plan -> plan.registerAuthenticationHandlerWithPrincipalResolver(principalBearingCredentialsAuthenticationHandler(), trustedPrincipalResolver());
    }
}
