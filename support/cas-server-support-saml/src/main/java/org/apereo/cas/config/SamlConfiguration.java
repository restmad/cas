package org.apereo.cas.config;

import org.apereo.cas.CentralAuthenticationService;
import org.apereo.cas.authentication.AuthenticationServiceSelectionPlan;
import org.apereo.cas.authentication.AuthenticationSystemSupport;
import org.apereo.cas.authentication.ProtocolAttributeEncoder;
import org.apereo.cas.authentication.principal.PrincipalFactoryUtils;
import org.apereo.cas.authentication.principal.ResponseBuilder;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.saml.OpenSamlConfigBean;
import org.apereo.cas.support.saml.authentication.SamlResponseBuilder;
import org.apereo.cas.support.saml.authentication.principal.SamlServiceResponseBuilder;
import org.apereo.cas.support.saml.util.Saml10ObjectBuilder;
import org.apereo.cas.support.saml.web.SamlValidateController;
import org.apereo.cas.support.saml.web.SamlValidateEndpoint;
import org.apereo.cas.support.saml.web.view.Saml10FailureResponseView;
import org.apereo.cas.support.saml.web.view.Saml10SuccessResponseView;
import org.apereo.cas.ticket.proxy.ProxyHandler;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.validation.AuthenticationAttributeReleasePolicy;
import org.apereo.cas.validation.CasProtocolValidationSpecification;
import org.apereo.cas.validation.RequestedAuthenticationContextValidator;
import org.apereo.cas.validation.ServiceTicketValidationAuthorizersExecutionPlan;
import org.apereo.cas.web.ServiceValidateConfigurationContext;
import org.apereo.cas.web.ServiceValidationViewFactory;
import org.apereo.cas.web.ServiceValidationViewFactoryConfigurer;
import org.apereo.cas.web.support.ArgumentExtractor;
import org.apereo.cas.web.view.attributes.NoOpProtocolAttributesRenderer;

import lombok.val;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.actuate.autoconfigure.endpoint.condition.ConditionalOnEnabledEndpoint;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.View;

import java.nio.charset.StandardCharsets;

/**
 * This is {@link SamlConfiguration} that creates the necessary OpenSAML context and beans.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
@Configuration("samlConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class SamlConfiguration {
    @Autowired
    @Qualifier("serviceValidationViewFactory")
    private ObjectProvider<ServiceValidationViewFactory> serviceValidationViewFactory;

    @Autowired
    @Qualifier("argumentExtractor")
    private ObjectProvider<ArgumentExtractor> argumentExtractor;

    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("webApplicationServiceFactory")
    private ObjectProvider<ServiceFactory<WebApplicationService>> webApplicationServiceFactory;

    @Autowired
    @Qualifier("casAttributeEncoder")
    private ObjectProvider<ProtocolAttributeEncoder> protocolAttributeEncoder;

    @Autowired
    @Qualifier("authenticationServiceSelectionPlan")
    private ObjectProvider<AuthenticationServiceSelectionPlan> authenticationServiceSelectionPlan;

    @Autowired
    @Qualifier("proxy20Handler")
    private ObjectProvider<ProxyHandler> proxy20Handler;

    @Autowired
    @Qualifier("shibboleth.OpenSAMLConfig")
    private ObjectProvider<OpenSamlConfigBean> openSamlConfigBean;

    @Autowired
    @Qualifier("servicesManager")
    private ObjectProvider<ServicesManager> servicesManager;

    @Autowired
    @Qualifier("centralAuthenticationService")
    private ObjectProvider<CentralAuthenticationService> centralAuthenticationService;

    @Autowired
    @Qualifier("authenticationAttributeReleasePolicy")
    private ObjectProvider<AuthenticationAttributeReleasePolicy> authenticationAttributeReleasePolicy;

    @Autowired
    @Qualifier("requestedContextValidator")
    private ObjectProvider<RequestedAuthenticationContextValidator> requestedContextValidator;

    @Autowired
    @Qualifier("defaultAuthenticationSystemSupport")
    private ObjectProvider<AuthenticationSystemSupport> authenticationSystemSupport;

    @Autowired
    @Qualifier("cas20WithoutProxyProtocolValidationSpecification")
    private ObjectProvider<CasProtocolValidationSpecification> cas20WithoutProxyProtocolValidationSpecification;

    @Autowired
    @Qualifier("serviceValidationAuthorizers")
    private ObjectProvider<ServiceTicketValidationAuthorizersExecutionPlan> validationAuthorizers;

    @ConditionalOnMissingBean(name = "samlResponseBuilder")
    @RefreshScope
    @Bean
    public SamlResponseBuilder samlResponseBuilder() {
        val samlCore = casProperties.getSamlCore();
        return new SamlResponseBuilder(saml10ObjectBuilder(),
            samlCore.getIssuer(),
            samlCore.getAttributeNamespace(),
            samlCore.getIssueLength(),
            samlCore.getSkewAllowance(),
            protocolAttributeEncoder.getIfAvailable(),
            this.servicesManager.getIfAvailable());
    }

    @ConditionalOnMissingBean(name = "casSamlServiceSuccessView")
    @RefreshScope
    @Bean
    public View casSamlServiceSuccessView() {
        return new Saml10SuccessResponseView(protocolAttributeEncoder.getIfAvailable(),
            servicesManager.getIfAvailable(),
            argumentExtractor.getIfAvailable(),
            StandardCharsets.UTF_8.name(),
            authenticationAttributeReleasePolicy.getIfAvailable(),
            authenticationServiceSelectionPlan.getIfAvailable(),
            new NoOpProtocolAttributesRenderer(),
            samlResponseBuilder());
    }

    @ConditionalOnMissingBean(name = "casSamlServiceFailureView")
    @RefreshScope
    @Bean
    public View casSamlServiceFailureView() {
        return new Saml10FailureResponseView(protocolAttributeEncoder.getIfAvailable(),
            servicesManager.getIfAvailable(),
            argumentExtractor.getIfAvailable(),
            StandardCharsets.UTF_8.name(),
            authenticationAttributeReleasePolicy.getIfAvailable(),
            authenticationServiceSelectionPlan.getIfAvailable(),
            new NoOpProtocolAttributesRenderer(),
            samlResponseBuilder());
    }

    @ConditionalOnMissingBean(name = "samlServiceResponseBuilder")
    @Bean
    public ResponseBuilder samlServiceResponseBuilder() {
        return new SamlServiceResponseBuilder(servicesManager.getIfAvailable());
    }

    @ConditionalOnMissingBean(name = "saml10ObjectBuilder")
    @Bean
    public Saml10ObjectBuilder saml10ObjectBuilder() {
        return new Saml10ObjectBuilder(this.openSamlConfigBean.getIfAvailable());
    }

    @Bean
    public SamlValidateController samlValidateController() {
        val context = ServiceValidateConfigurationContext.builder()
            .validationSpecifications(CollectionUtils.wrapSet(cas20WithoutProxyProtocolValidationSpecification.getIfAvailable()))
            .authenticationSystemSupport(authenticationSystemSupport.getIfAvailable())
            .servicesManager(servicesManager.getIfAvailable())
            .centralAuthenticationService(centralAuthenticationService.getIfAvailable())
            .argumentExtractor(argumentExtractor.getIfAvailable())
            .proxyHandler(proxy20Handler.getIfAvailable())
            .requestedContextValidator(requestedContextValidator.getIfAvailable())
            .authnContextAttribute(casProperties.getAuthn().getMfa().getAuthenticationContextAttribute())
            .validationAuthorizers(validationAuthorizers.getIfAvailable())
            .renewEnabled(casProperties.getSso().isRenewAuthnEnabled())
            .validationViewFactory(serviceValidationViewFactory.getIfAvailable())
            .build();

        return new SamlValidateController(context);
    }

    @Bean
    public ServiceValidationViewFactoryConfigurer samlServiceValidationViewFactoryConfigurer() {
        return factory ->
            factory.registerView(SamlValidateController.class,
                Pair.of(casSamlServiceSuccessView(), casSamlServiceFailureView()));
    }

    @Bean
    @ConditionalOnEnabledEndpoint
    public SamlValidateEndpoint samlValidateEndpoint() {
        return new SamlValidateEndpoint(casProperties, servicesManager.getIfAvailable(),
            authenticationSystemSupport.getIfAvailable(),
            webApplicationServiceFactory.getIfAvailable(),
            PrincipalFactoryUtils.newPrincipalFactory(),
            samlResponseBuilder(),
            openSamlConfigBean.getIfAvailable());
    }
}
