package org.apereo.cas.otp.config;

import org.apereo.cas.CentralAuthenticationService;
import org.apereo.cas.audit.AuditableExecution;
import org.apereo.cas.authentication.AuthenticationServiceSelectionPlan;
import org.apereo.cas.authentication.AuthenticationSystemSupport;
import org.apereo.cas.authentication.OneTimeToken;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.otp.repository.token.CachingOneTimeTokenRepository;
import org.apereo.cas.otp.repository.token.OneTimeTokenRepository;
import org.apereo.cas.otp.web.flow.OneTimeTokenAuthenticationWebflowAction;
import org.apereo.cas.otp.web.flow.OneTimeTokenAuthenticationWebflowEventResolver;
import org.apereo.cas.otp.web.flow.rest.OneTimeTokenQRGeneratorController;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.ticket.registry.TicketRegistrySupport;
import org.apereo.cas.web.cookie.CasCookieBuilder;
import org.apereo.cas.web.flow.resolver.CasWebflowEventResolver;
import org.apereo.cas.web.flow.resolver.impl.CasWebflowEventResolutionConfigurationContext;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.webflow.execution.Action;

import java.util.Collection;
import java.util.concurrent.TimeUnit;

/**
 * This is {@link OneTimeTokenAuthenticationConfiguration}.
 *
 * @author Misagh Moayyed
 * @since 5.1.0
 */
@Configuration("oneTimeTokenAuthenticationConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
@EnableScheduling
@Slf4j
public class OneTimeTokenAuthenticationConfiguration {
    private static final int EXPIRE_TOKENS_IN_SECONDS = 30;

    private static final int INITIAL_CACHE_SIZE = 50;
    private static final long MAX_CACHE_SIZE = 1_000_000;

    @Autowired
    @Qualifier("centralAuthenticationService")
    private ObjectProvider<CentralAuthenticationService> centralAuthenticationService;

    @Autowired
    @Qualifier("defaultAuthenticationSystemSupport")
    private ObjectProvider<AuthenticationSystemSupport> authenticationSystemSupport;

    @Autowired
    @Qualifier("defaultTicketRegistrySupport")
    private ObjectProvider<TicketRegistrySupport> ticketRegistrySupport;

    @Autowired
    @Qualifier("servicesManager")
    private ObjectProvider<ServicesManager> servicesManager;

    @Autowired
    @Qualifier("warnCookieGenerator")
    private ObjectProvider<CasCookieBuilder> warnCookieGenerator;

    @Autowired
    @Qualifier("authenticationServiceSelectionPlan")
    private ObjectProvider<AuthenticationServiceSelectionPlan> authenticationRequestServiceSelectionStrategies;

    @Autowired
    private ConfigurableApplicationContext applicationContext;

    @Autowired
    private ApplicationEventPublisher applicationEventPublisher;

    @Autowired
    @Qualifier("registeredServiceAccessStrategyEnforcer")
    private ObjectProvider<AuditableExecution> registeredServiceAccessStrategyEnforcer;

    @Autowired
    private CasConfigurationProperties casProperties;

    @Bean
    @RefreshScope
    public CasWebflowEventResolver oneTimeTokenAuthenticationWebflowEventResolver() {
        val context = CasWebflowEventResolutionConfigurationContext.builder()
            .authenticationSystemSupport(authenticationSystemSupport.getIfAvailable())
            .centralAuthenticationService(centralAuthenticationService.getIfAvailable())
            .servicesManager(servicesManager.getIfAvailable())
            .ticketRegistrySupport(ticketRegistrySupport.getIfAvailable())
            .warnCookieGenerator(warnCookieGenerator.getIfAvailable())
            .authenticationRequestServiceSelectionStrategies(authenticationRequestServiceSelectionStrategies.getIfAvailable())
            .registeredServiceAccessStrategyEnforcer(registeredServiceAccessStrategyEnforcer.getIfAvailable())
            .casProperties(casProperties)
            .eventPublisher(applicationEventPublisher)
            .applicationContext(applicationContext)
            .build();

        return new OneTimeTokenAuthenticationWebflowEventResolver(context);
    }

    @Bean
    @RefreshScope
    public Action oneTimeTokenAuthenticationWebflowAction() {
        return new OneTimeTokenAuthenticationWebflowAction(oneTimeTokenAuthenticationWebflowEventResolver());
    }

    @Bean
    public OneTimeTokenQRGeneratorController oneTimeTokenQRGeneratorController() {
        return new OneTimeTokenQRGeneratorController();
    }

    @ConditionalOnMissingBean(name = "oneTimeTokenAuthenticatorTokenRepository")
    @Bean
    public OneTimeTokenRepository oneTimeTokenAuthenticatorTokenRepository() {
        final LoadingCache<String, Collection<OneTimeToken>> storage = Caffeine.newBuilder()
            .initialCapacity(INITIAL_CACHE_SIZE)
            .maximumSize(MAX_CACHE_SIZE)
            .recordStats()
            .expireAfterWrite(EXPIRE_TOKENS_IN_SECONDS, TimeUnit.SECONDS)
            .build(s -> {
                LOGGER.error("Load operation of the cache is not supported.");
                return null;
            });
        return new CachingOneTimeTokenRepository(storage);
    }
}

