package org.apereo.cas.config;

import org.apereo.cas.CentralAuthenticationService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.rest.factory.TicketGrantingTicketResourceEntityResponseFactory;
import org.apereo.cas.rest.plan.ServiceTicketResourceEntityResponseFactoryConfigurer;
import org.apereo.cas.rest.plan.ServiceTicketResourceEntityResponseFactoryPlan;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.ticket.registry.TicketRegistrySupport;
import org.apereo.cas.token.TokenTicketBuilder;
import org.apereo.cas.tokens.JwtServiceTicketResourceEntityResponseFactory;
import org.apereo.cas.tokens.JwtTicketGrantingTicketResourceEntityResponseFactory;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * This is {@link CasRestTokensConfiguration}.
 *
 * @author Misagh Moayyed
 * @since 5.2.0
 */
@Configuration("casRestTokensConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class CasRestTokensConfiguration implements ServiceTicketResourceEntityResponseFactoryConfigurer {
    @Autowired
    @Qualifier("centralAuthenticationService")
    private ObjectProvider<CentralAuthenticationService> centralAuthenticationService;

    @Autowired
    @Qualifier("tokenTicketBuilder")
    private ObjectProvider<TokenTicketBuilder> tokenTicketBuilder;

    @Autowired
    @Qualifier("servicesManager")
    private ObjectProvider<ServicesManager> servicesManager;

    @Autowired
    @Qualifier("defaultTicketRegistrySupport")
    private ObjectProvider<TicketRegistrySupport> ticketRegistrySupport;

    @Bean
    public TicketGrantingTicketResourceEntityResponseFactory ticketGrantingTicketResourceEntityResponseFactory() {
        return new JwtTicketGrantingTicketResourceEntityResponseFactory(servicesManager.getIfAvailable(), tokenTicketBuilder.getIfAvailable());
    }

    @Override
    public void configureEntityResponseFactory(final ServiceTicketResourceEntityResponseFactoryPlan plan) {
        plan.registerFactory(new JwtServiceTicketResourceEntityResponseFactory(centralAuthenticationService.getIfAvailable(),
            tokenTicketBuilder.getIfAvailable(),
            ticketRegistrySupport.getIfAvailable(),
            servicesManager.getIfAvailable()));
    }
}
