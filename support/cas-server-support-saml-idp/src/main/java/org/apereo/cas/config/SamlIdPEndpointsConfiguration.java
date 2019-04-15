package org.apereo.cas.config;

import org.apereo.cas.authentication.AuthenticationSystemSupport;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.RegexRegisteredService;
import org.apereo.cas.services.ServiceRegistryExecutionPlan;
import org.apereo.cas.services.ServiceRegistryExecutionPlanConfigurer;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.saml.OpenSamlConfigBean;
import org.apereo.cas.support.saml.SamlIdPConstants;
import org.apereo.cas.support.saml.services.SamlIdPServiceRegistry;
import org.apereo.cas.support.saml.services.idp.metadata.cache.SamlRegisteredServiceCachingMetadataResolver;
import org.apereo.cas.support.saml.web.idp.profile.HttpServletRequestXMLMessageDecodersMap;
import org.apereo.cas.support.saml.web.idp.profile.IdentityProviderInitiatedProfileHandlerController;
import org.apereo.cas.support.saml.web.idp.profile.SamlProfileHandlerConfigurationContext;
import org.apereo.cas.support.saml.web.idp.profile.artifact.Saml1ArtifactResolutionProfileHandlerController;
import org.apereo.cas.support.saml.web.idp.profile.builders.SamlProfileObjectBuilder;
import org.apereo.cas.support.saml.web.idp.profile.builders.enc.SamlIdPObjectSigner;
import org.apereo.cas.support.saml.web.idp.profile.builders.enc.validate.SamlIdPObjectSignatureValidator;
import org.apereo.cas.support.saml.web.idp.profile.builders.enc.validate.SamlObjectSignatureValidator;
import org.apereo.cas.support.saml.web.idp.profile.ecp.ECPProfileHandlerController;
import org.apereo.cas.support.saml.web.idp.profile.query.Saml2AttributeQueryProfileHandlerController;
import org.apereo.cas.support.saml.web.idp.profile.slo.SLOSamlPostProfileHandlerController;
import org.apereo.cas.support.saml.web.idp.profile.slo.SLOSamlRedirectProfileHandlerController;
import org.apereo.cas.support.saml.web.idp.profile.sso.SSOSamlPostProfileHandlerController;
import org.apereo.cas.support.saml.web.idp.profile.sso.SSOSamlPostSimpleSignProfileHandlerController;
import org.apereo.cas.support.saml.web.idp.profile.sso.SSOSamlProfileCallbackHandlerController;
import org.apereo.cas.support.saml.web.idp.profile.sso.UrlDecodingHTTPRedirectDeflateDecoder;
import org.apereo.cas.support.saml.web.idp.profile.sso.request.DefaultSSOSamlHttpRequestExtractor;
import org.apereo.cas.support.saml.web.idp.profile.sso.request.SSOSamlHttpRequestExtractor;
import org.apereo.cas.ticket.artifact.SamlArtifactTicketFactory;
import org.apereo.cas.ticket.query.SamlAttributeQueryTicketFactory;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.util.RandomUtils;
import org.apereo.cas.web.cookie.CasCookieBuilder;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.jasig.cas.client.validation.AbstractUrlBasedTicketValidator;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostSimpleSignDecoder;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;

/**
 * This is {@link SamlIdPEndpointsConfiguration}.
 *
 * @author Misagh Moayyed
 * @since 5.2.0
 */
@Configuration("samlIdPEndpointsConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
@Slf4j
public class SamlIdPEndpointsConfiguration {
    @Autowired
    private ApplicationEventPublisher eventPublisher;

    @Autowired
    @Qualifier("casClientTicketValidator")
    private ObjectProvider<AbstractUrlBasedTicketValidator> casClientTicketValidator;

    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("servicesManager")
    private ObjectProvider<ServicesManager> servicesManager;

    @Autowired
    @Qualifier("shibboleth.OpenSAMLConfig")
    private ObjectProvider<OpenSamlConfigBean> openSamlConfigBean;

    @Autowired
    @Qualifier("samlProfileSamlResponseBuilder")
    private ObjectProvider<SamlProfileObjectBuilder<Response>> samlProfileSamlResponseBuilder;

    @Autowired
    @Qualifier("defaultSamlRegisteredServiceCachingMetadataResolver")
    private ObjectProvider<SamlRegisteredServiceCachingMetadataResolver> defaultSamlRegisteredServiceCachingMetadataResolver;

    @Autowired
    @Qualifier("webApplicationServiceFactory")
    private ObjectProvider<ServiceFactory<WebApplicationService>> webApplicationServiceFactory;

    @Autowired
    @Qualifier("defaultAuthenticationSystemSupport")
    private ObjectProvider<AuthenticationSystemSupport> authenticationSystemSupport;

    @Autowired
    @Qualifier("samlObjectSigner")
    private ObjectProvider<SamlIdPObjectSigner> samlObjectSigner;

    @Autowired
    @Qualifier("ticketGrantingTicketCookieGenerator")
    private ObjectProvider<CasCookieBuilder> ticketGrantingTicketCookieGenerator;

    @Autowired
    @Qualifier("casSamlIdPMetadataResolver")
    private ObjectProvider<MetadataResolver> casSamlIdPMetadataResolver;

    @Autowired
    @Qualifier("samlProfileSamlSoap11ResponseBuilder")
    private ObjectProvider<SamlProfileObjectBuilder<org.opensaml.saml.saml2.ecp.Response>> samlProfileSamlSoap11ResponseBuilder;

    @Autowired
    @Qualifier("samlProfileSamlSoap11FaultResponseBuilder")
    private ObjectProvider<SamlProfileObjectBuilder<org.opensaml.saml.saml2.ecp.Response>> samlProfileSamlSoap11FaultResponseBuilder;

    @Autowired
    @Qualifier("samlProfileSamlArtifactResponseBuilder")
    private ObjectProvider<SamlProfileObjectBuilder<Response>> samlProfileSamlArtifactResponseBuilder;

    @Autowired
    @Qualifier("samlProfileSamlArtifactFaultResponseBuilder")
    private ObjectProvider<SamlProfileObjectBuilder<Response>> samlProfileSamlArtifactFaultResponseBuilder;

    @Autowired
    @Qualifier("samlProfileSamlAttributeQueryResponseBuilder")
    private ObjectProvider<SamlProfileObjectBuilder<Response>> samlProfileSamlAttributeQueryResponseBuilder;

    @Autowired
    @Qualifier("samlProfileSamlAttributeQueryFaultResponseBuilder")
    private ObjectProvider<SamlProfileObjectBuilder<Response>> samlProfileSamlAttributeQueryFaultResponseBuilder;

    @Autowired
    @Qualifier("samlAttributeQueryTicketFactory")
    private ObjectProvider<SamlAttributeQueryTicketFactory> samlAttributeQueryTicketFactory;

    @Autowired
    @Qualifier("ticketRegistry")
    private ObjectProvider<TicketRegistry> ticketRegistry;

    @Autowired
    @Qualifier("samlArtifactTicketFactory")
    private ObjectProvider<SamlArtifactTicketFactory> samlArtifactTicketFactory;

    @ConditionalOnMissingBean(name = "samlIdPObjectSignatureValidator")
    @Bean
    public SamlObjectSignatureValidator samlIdPObjectSignatureValidator() {
        val algs = casProperties.getAuthn().getSamlIdp().getAlgs();
        return new SamlIdPObjectSignatureValidator(
            algs.getOverrideSignatureReferenceDigestMethods(),
            algs.getOverrideSignatureAlgorithms(),
            algs.getOverrideBlackListedSignatureSigningAlgorithms(),
            algs.getOverrideWhiteListedSignatureSigningAlgorithms(),
            casSamlIdPMetadataResolver.getIfAvailable(),
            casProperties
        );
    }

    @ConditionalOnMissingBean(name = "samlObjectSignatureValidator")
    @Bean
    public SamlObjectSignatureValidator samlObjectSignatureValidator() {
        val algs = casProperties.getAuthn().getSamlIdp().getAlgs();
        return new SamlObjectSignatureValidator(
            algs.getOverrideSignatureReferenceDigestMethods(),
            algs.getOverrideSignatureAlgorithms(),
            algs.getOverrideBlackListedSignatureSigningAlgorithms(),
            algs.getOverrideWhiteListedSignatureSigningAlgorithms(),
            casProperties
        );
    }

    @ConditionalOnMissingBean(name = "ssoSamlHttpRequestExtractor")
    @Bean
    public SSOSamlHttpRequestExtractor ssoSamlHttpRequestExtractor() {
        return new DefaultSSOSamlHttpRequestExtractor(openSamlConfigBean.getObject().getParserPool());
    }

    @Bean
    @ConditionalOnMissingBean(name = "ssoPostProfileHandlerDecoders")
    public HttpServletRequestXMLMessageDecodersMap ssoPostProfileHandlerDecoders() {
        val props = casProperties.getAuthn().getSamlIdp().getProfile().getSso();
        val decoders = new HttpServletRequestXMLMessageDecodersMap(HttpMethod.class);
        decoders.put(HttpMethod.GET, new UrlDecodingHTTPRedirectDeflateDecoder(props.isUrlDecodeRedirectRequest()));
        decoders.put(HttpMethod.POST, new HTTPPostDecoder());
        return decoders;
    }

    @Bean
    @RefreshScope
    public SSOSamlPostProfileHandlerController ssoPostProfileHandlerController() {
        val context = getSamlProfileHandlerConfigurationContextBuilder()
            .responseBuilder(samlProfileSamlResponseBuilder.getIfAvailable())
            .samlMessageDecoders(ssoPostProfileHandlerDecoders())
            .build();
        return new SSOSamlPostProfileHandlerController(context);
    }

    @Bean
    @ConditionalOnMissingBean(name = "ssoPostSimpleSignProfileHandlerDecoders")
    public HttpServletRequestXMLMessageDecodersMap ssoPostSimpleSignProfileHandlerDecoders() {
        val props = casProperties.getAuthn().getSamlIdp().getProfile().getSsoPostSimpleSign();
        val decoders = new HttpServletRequestXMLMessageDecodersMap(HttpMethod.class);
        decoders.put(HttpMethod.GET, new UrlDecodingHTTPRedirectDeflateDecoder(props.isUrlDecodeRedirectRequest()));
        decoders.put(HttpMethod.POST, new HTTPPostSimpleSignDecoder());
        return decoders;
    }

    @Bean
    @RefreshScope
    public SSOSamlPostSimpleSignProfileHandlerController ssoPostSimpleSignProfileHandlerController() {
        val context = getSamlProfileHandlerConfigurationContextBuilder()
            .responseBuilder(samlProfileSamlResponseBuilder.getIfAvailable())
            .samlMessageDecoders(ssoPostSimpleSignProfileHandlerDecoders())
            .build();

        return new SSOSamlPostSimpleSignProfileHandlerController(context);
    }

    @Bean
    @ConditionalOnMissingBean(name = "sloRedirectProfileHandlerDecoders")
    public HttpServletRequestXMLMessageDecodersMap sloRedirectProfileHandlerDecoders() {
        val props = casProperties.getAuthn().getSamlIdp().getProfile().getSlo();
        val decoders = new HttpServletRequestXMLMessageDecodersMap(HttpMethod.class);
        decoders.put(HttpMethod.GET, new UrlDecodingHTTPRedirectDeflateDecoder(props.isUrlDecodeRedirectRequest()));
        return decoders;
    }

    @Bean
    @RefreshScope
    public SLOSamlRedirectProfileHandlerController sloRedirectProfileHandlerController() {
        val context = getSamlProfileHandlerConfigurationContextBuilder()
            .samlMessageDecoders(sloRedirectProfileHandlerDecoders())
            .build();
        return new SLOSamlRedirectProfileHandlerController(context);
    }

    @Bean
    @ConditionalOnMissingBean(name = "sloPostProfileHandlerDecoders")
    public HttpServletRequestXMLMessageDecodersMap sloPostProfileHandlerDecoders() {
        val decoders = new HttpServletRequestXMLMessageDecodersMap(HttpMethod.class);
        decoders.put(HttpMethod.POST, new HTTPPostDecoder());
        return decoders;
    }

    @Bean
    @RefreshScope
    public SLOSamlPostProfileHandlerController sloPostProfileHandlerController() {
        val context = getSamlProfileHandlerConfigurationContextBuilder()
            .samlMessageDecoders(sloPostProfileHandlerDecoders())
            .build();
        return new SLOSamlPostProfileHandlerController(context);
    }

    @Bean
    @RefreshScope
    public IdentityProviderInitiatedProfileHandlerController idpInitiatedSamlProfileHandlerController() {
        val context = getSamlProfileHandlerConfigurationContextBuilder()
            .samlObjectSignatureValidator(samlIdPObjectSignatureValidator())
            .build();
        return new IdentityProviderInitiatedProfileHandlerController(context);
    }

    @Bean
    @RefreshScope
    public SSOSamlProfileCallbackHandlerController ssoPostProfileCallbackHandlerController() {
        val context = getSamlProfileHandlerConfigurationContextBuilder().build();
        return new SSOSamlProfileCallbackHandlerController(context);
    }

    @Bean
    @RefreshScope
    public ECPProfileHandlerController ecpProfileHandlerController() {
        val context = getSamlProfileHandlerConfigurationContextBuilder()
            .responseBuilder(samlProfileSamlSoap11ResponseBuilder.getIfAvailable())
            .samlFaultResponseBuilder(samlProfileSamlSoap11FaultResponseBuilder.getIfAvailable())
            .build();
        return new ECPProfileHandlerController(context);
    }

    @Bean
    @RefreshScope
    public Saml1ArtifactResolutionProfileHandlerController saml1ArtifactResolutionController() {
        val context = getSamlProfileHandlerConfigurationContextBuilder()
            .responseBuilder(samlProfileSamlArtifactResponseBuilder.getIfAvailable())
            .samlFaultResponseBuilder(samlProfileSamlArtifactFaultResponseBuilder.getIfAvailable())
            .build();
        return new Saml1ArtifactResolutionProfileHandlerController(context);
    }

    @ConditionalOnProperty(prefix = "cas.authn.samlIdp", name = "attributeQueryProfileEnabled", havingValue = "true")
    @Bean
    @RefreshScope
    public Saml2AttributeQueryProfileHandlerController saml2AttributeQueryProfileHandlerController() {
        val context = getSamlProfileHandlerConfigurationContextBuilder()
            .responseBuilder(samlProfileSamlAttributeQueryResponseBuilder.getIfAvailable())
            .samlFaultResponseBuilder(samlProfileSamlAttributeQueryFaultResponseBuilder.getIfAvailable())
            .build();
        return new Saml2AttributeQueryProfileHandlerController(context);
    }

    @Bean
    public Service samlIdPCallbackService() {
        val service = casProperties.getServer().getPrefix().concat(SamlIdPConstants.ENDPOINT_SAML2_SSO_PROFILE_POST_CALLBACK);
        return this.webApplicationServiceFactory.getIfAvailable().createService(service);
    }

    @Bean
    @ConditionalOnMissingBean(name = "samlIdPServiceRegistryExecutionPlanConfigurer")
    public ServiceRegistryExecutionPlanConfigurer samlIdPServiceRegistryExecutionPlanConfigurer() {
        return new ServiceRegistryExecutionPlanConfigurer() {
            @Override
            public void configureServiceRegistry(final ServiceRegistryExecutionPlan plan) {
                val callbackService = samlIdPCallbackService().getId().concat(".*");
                LOGGER.debug("Initializing SAML IdP callback service [{}]", callbackService);
                val service = new RegexRegisteredService();
                service.setId(RandomUtils.getNativeInstance().nextLong());
                service.setEvaluationOrder(Ordered.HIGHEST_PRECEDENCE);
                service.setName(service.getClass().getSimpleName());
                service.setDescription("SAML Authentication Request Callback");
                service.setServiceId(callbackService);
                plan.registerServiceRegistry(new SamlIdPServiceRegistry(eventPublisher, service));
            }
        };
    }

    private SamlProfileHandlerConfigurationContext.SamlProfileHandlerConfigurationContextBuilder getSamlProfileHandlerConfigurationContextBuilder() {
        return SamlProfileHandlerConfigurationContext.builder()
            .samlObjectSigner(samlObjectSigner.getObject())
            .authenticationSystemSupport(authenticationSystemSupport.getObject())
            .servicesManager(servicesManager.getIfAvailable())
            .webApplicationServiceFactory(webApplicationServiceFactory.getIfAvailable())
            .samlRegisteredServiceCachingMetadataResolver(defaultSamlRegisteredServiceCachingMetadataResolver.getIfAvailable())
            .openSamlConfigBean(openSamlConfigBean.getIfAvailable())
            .casProperties(casProperties)
            .artifactTicketFactory(samlArtifactTicketFactory.getIfAvailable())
            .samlObjectSignatureValidator(samlObjectSignatureValidator())
            .samlHttpRequestExtractor(ssoSamlHttpRequestExtractor())
            .responseBuilder(samlProfileSamlResponseBuilder.getIfAvailable())
            .ticketValidator(casClientTicketValidator.getIfAvailable())
            .ticketRegistry(ticketRegistry.getIfAvailable())
            .ticketGrantingTicketCookieGenerator(ticketGrantingTicketCookieGenerator.getIfAvailable())
            .samlAttributeQueryTicketFactory(samlAttributeQueryTicketFactory.getIfAvailable())
            .callbackService(samlIdPCallbackService());
    }
}
