package org.apereo.cas.config;

import org.apereo.cas.authentication.DefaultPrincipalElectionStrategy;
import org.apereo.cas.authentication.PrincipalElectionStrategy;
import org.apereo.cas.authentication.principal.DefaultPrincipalAttributesRepository;
import org.apereo.cas.authentication.principal.DefaultPrincipalResolutionExecutionPlan;
import org.apereo.cas.authentication.principal.PrincipalAttributesRepository;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalFactoryUtils;
import org.apereo.cas.authentication.principal.PrincipalResolutionExecutionPlan;
import org.apereo.cas.authentication.principal.PrincipalResolutionExecutionPlanConfigurer;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.authentication.principal.cache.CachingPrincipalAttributesRepository;
import org.apereo.cas.authentication.principal.resolvers.ChainingPrincipalResolver;
import org.apereo.cas.authentication.principal.resolvers.EchoingPrincipalResolver;
import org.apereo.cas.authentication.principal.resolvers.PersonDirectoryPrincipalResolver;
import org.apereo.cas.configuration.CasConfigurationProperties;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.services.persondir.IPersonAttributeDao;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * This is {@link CasCoreAuthenticationPrincipalConfiguration}.
 *
 * @author Misagh Moayyed
 * @since 5.1.0
 */
@Configuration("casCoreAuthenticationPrincipalConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
@Slf4j
public class CasCoreAuthenticationPrincipalConfiguration implements PrincipalResolutionExecutionPlanConfigurer {

    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("attributeRepositories")
    private ObjectProvider<List<IPersonAttributeDao>> attributeRepositories;

    @Autowired
    @Qualifier("attributeRepository")
    private ObjectProvider<IPersonAttributeDao> attributeRepository;

    @ConditionalOnMissingBean(name = "principalElectionStrategy")
    @Bean
    @RefreshScope
    public PrincipalElectionStrategy principalElectionStrategy() {
        return new DefaultPrincipalElectionStrategy(principalFactory());
    }

    @ConditionalOnMissingBean(name = "principalFactory")
    @Bean
    @RefreshScope
    public PrincipalFactory principalFactory() {
        return PrincipalFactoryUtils.newPrincipalFactory();
    }

    @Bean
    @RefreshScope
    @ConditionalOnMissingBean(name = "globalPrincipalAttributeRepository")
    public PrincipalAttributesRepository globalPrincipalAttributeRepository() {
        val props = casProperties.getAuthn().getAttributeRepository();
        val cacheTime = props.getExpirationTime();
        if (cacheTime <= 0) {
            LOGGER.warn("Caching for the global principal attribute repository is disabled");
            return new DefaultPrincipalAttributesRepository();
        }
        return new CachingPrincipalAttributesRepository(props.getExpirationTimeUnit().toUpperCase(), cacheTime);
    }

    @RefreshScope
    @Bean
    @ConditionalOnMissingBean(name = "personDirectoryAttributeRepositoryPrincipalResolver")
    public PrincipalResolver personDirectoryAttributeRepositoryPrincipalResolver() {
        val personDirectory = casProperties.getPersonDirectory();
        return new PersonDirectoryPrincipalResolver(
            attributeRepository.getIfAvailable(),
            principalFactory(),
            personDirectory.isReturnNull(),
            personDirectory.getPrincipalAttribute(),
            personDirectory.isUseExistingPrincipalId(),
            personDirectory.isAttributeResolutionEnabled(),
            StringUtils.commaDelimitedListToSet(personDirectory.getActiveAttributeRepositoryIds())
        );
    }

    @Bean
    @ConditionalOnMissingBean(name = "defaultPrincipalResolver")
    @RefreshScope
    public PrincipalResolver defaultPrincipalResolver(final List<PrincipalResolutionExecutionPlanConfigurer> configurers) {
        val plan = new DefaultPrincipalResolutionExecutionPlan();
        val sortedConfigurers = new ArrayList<PrincipalResolutionExecutionPlanConfigurer>(configurers);
        AnnotationAwareOrderComparator.sortIfNecessary(sortedConfigurers);

        sortedConfigurers.forEach(c -> {
            LOGGER.trace("Configuring principal resolution execution plan [{}]", c.getName());
            c.configurePrincipalResolutionExecutionPlan(plan);
        });
        plan.registerPrincipalResolver(new EchoingPrincipalResolver());

        val resolver = new ChainingPrincipalResolver();
        resolver.setChain(plan.getRegisteredPrincipalResolvers());
        return resolver;
    }

    @Override
    public void configurePrincipalResolutionExecutionPlan(final PrincipalResolutionExecutionPlan plan) {
        if (!Objects.requireNonNull(attributeRepositories.getIfAvailable()).isEmpty()) {
            LOGGER.trace("Attribute repository sources are defined and available for person-directory principal resolution chain. ");
            plan.registerPrincipalResolver(personDirectoryAttributeRepositoryPrincipalResolver());
        } else {
            LOGGER.debug("Attribute repository sources are not available for person-directory principal resolution");
        }
    }
}
