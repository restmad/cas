package org.apereo.cas.config;

import org.apereo.cas.authentication.AcceptUsersAuthenticationHandler;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.CoreAuthenticationUtils;
import org.apereo.cas.authentication.handler.support.HttpBasedServiceCredentialsAuthenticationHandler;
import org.apereo.cas.authentication.handler.support.jaas.JaasAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalFactoryUtils;
import org.apereo.cas.authentication.principal.PrincipalNameTransformerUtils;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.authentication.principal.resolvers.PersonDirectoryPrincipalResolver;
import org.apereo.cas.authentication.principal.resolvers.ProxyingPrincipalResolver;
import org.apereo.cas.authentication.support.password.PasswordEncoderUtils;
import org.apereo.cas.authentication.support.password.PasswordPolicyConfiguration;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.util.http.HttpClient;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apereo.services.persondir.IPersonAttributeDao;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This is {@link CasCoreAuthenticationHandlersConfiguration}.
 *
 * @author Misagh Moayyed
 * @author Dmitriy Kopylenko
 * @since 5.1.0
 */
@Configuration("casCoreAuthenticationHandlersConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
@Slf4j
public class CasCoreAuthenticationHandlersConfiguration {

    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("supportsTrustStoreSslSocketFactoryHttpClient")
    private ObjectProvider<HttpClient> supportsTrustStoreSslSocketFactoryHttpClient;

    @Autowired
    @Qualifier("servicesManager")
    private ObjectProvider<ServicesManager> servicesManager;

    @ConditionalOnProperty(prefix = "cas.sso", name = "proxyAuthnEnabled", havingValue = "true", matchIfMissing = true)
    @Bean
    public AuthenticationHandler proxyAuthenticationHandler() {
        return new HttpBasedServiceCredentialsAuthenticationHandler(null,
            servicesManager.getIfAvailable(),
            proxyPrincipalFactory(), Integer.MIN_VALUE,
            supportsTrustStoreSslSocketFactoryHttpClient.getIfAvailable());
    }

    @ConditionalOnMissingBean(name = "proxyPrincipalFactory")
    @Bean
    public PrincipalFactory proxyPrincipalFactory() {
        return PrincipalFactoryUtils.newPrincipalFactory();
    }

    @ConditionalOnMissingBean(name = "proxyPrincipalResolver")
    @Bean
    public PrincipalResolver proxyPrincipalResolver() {
        return new ProxyingPrincipalResolver(proxyPrincipalFactory());
    }

    @RefreshScope
    @Bean
    public AuthenticationHandler acceptUsersAuthenticationHandler() {
        val props = casProperties.getAuthn().getAccept();
        val h = new AcceptUsersAuthenticationHandler(props.getName(),
            servicesManager.getIfAvailable(),
            acceptUsersPrincipalFactory(),
            null,
            getParsedUsers());
        h.setPasswordEncoder(PasswordEncoderUtils.newPasswordEncoder(props.getPasswordEncoder()));
        h.setPasswordPolicyConfiguration(acceptPasswordPolicyConfiguration());
        h.setCredentialSelectionPredicate(CoreAuthenticationUtils.newCredentialSelectionPredicate(props.getCredentialCriteria()));
        h.setPrincipalNameTransformer(PrincipalNameTransformerUtils.newPrincipalNameTransformer(props.getPrincipalTransformation()));
        val passwordPolicy = props.getPasswordPolicy();
        h.setPasswordPolicyHandlingStrategy(CoreAuthenticationUtils.newPasswordPolicyHandlingStrategy(passwordPolicy));
        if (passwordPolicy.isEnabled()) {
            val cfg = new PasswordPolicyConfiguration(passwordPolicy);
            if (passwordPolicy.isAccountStateHandlingEnabled()) {
                cfg.setAccountStateHandler((response, configuration) -> new ArrayList<>(0));
            } else {
                LOGGER.debug("Handling account states is disabled via CAS configuration");
            }
            h.setPasswordPolicyConfiguration(cfg);
        }
        return h;
    }

    @ConditionalOnMissingBean(name = "acceptUsersPrincipalFactory")
    @Bean
    public PrincipalFactory acceptUsersPrincipalFactory() {
        return PrincipalFactoryUtils.newPrincipalFactory();
    }

    private Map<String, String> getParsedUsers() {
        val pattern = Pattern.compile("::");
        val usersProperty = casProperties.getAuthn().getAccept().getUsers();

        if (StringUtils.isNotBlank(usersProperty) && usersProperty.contains(pattern.pattern())) {
            return Stream.of(usersProperty.split(","))
                .map(pattern::split)
                .collect(Collectors.toMap(userAndPassword -> userAndPassword[0], userAndPassword -> userAndPassword[1]));
        }
        return new HashMap<>(0);
    }

    @ConditionalOnMissingBean(name = "proxyAuthenticationEventExecutionPlanConfigurer")
    @Bean
    @ConditionalOnProperty(prefix = "cas.sso", name = "proxyAuthnEnabled", havingValue = "true", matchIfMissing = true)
    public AuthenticationEventExecutionPlanConfigurer proxyAuthenticationEventExecutionPlanConfigurer() {
        return plan -> plan.registerAuthenticationHandlerWithPrincipalResolver(proxyAuthenticationHandler(), proxyPrincipalResolver());
    }

    @ConditionalOnMissingBean(name = "acceptPasswordPolicyConfiguration")
    @Bean
    public PasswordPolicyConfiguration acceptPasswordPolicyConfiguration() {
        return new PasswordPolicyConfiguration();
    }

    @ConditionalOnMissingBean(name = "jaasPasswordPolicyConfiguration")
    @Bean
    public PasswordPolicyConfiguration jaasPasswordPolicyConfiguration() {
        return new PasswordPolicyConfiguration();
    }

    /**
     * The Jaas authentication configuration.
     */
    @Configuration("jaasAuthenticationConfiguration")
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    public class JaasAuthenticationConfiguration {

        @Autowired
        @Qualifier("attributeRepository")
        private ObjectProvider<IPersonAttributeDao> attributeRepository;

        @ConditionalOnMissingBean(name = "jaasPrincipalFactory")
        @Bean
        public PrincipalFactory jaasPrincipalFactory() {
            return PrincipalFactoryUtils.newPrincipalFactory();
        }

        @Bean
        @ConditionalOnMissingBean(name = "jaasPersonDirectoryPrincipalResolvers")
        public List<PrincipalResolver> jaasPersonDirectoryPrincipalResolvers() {
            val personDirectory = casProperties.getPersonDirectory();
            return casProperties.getAuthn().getJaas()
                .stream()
                .filter(jaas -> StringUtils.isNotBlank(jaas.getRealm()))
                .map(jaas -> {
                    val jaasPrincipal = jaas.getPrincipal();
                    val principalAttribute = StringUtils.defaultIfBlank(jaasPrincipal.getPrincipalAttribute(), personDirectory.getPrincipalAttribute());
                    return new PersonDirectoryPrincipalResolver(attributeRepository.getIfAvailable(),
                        jaasPrincipalFactory(),
                        jaasPrincipal.isReturnNull() || personDirectory.isReturnNull(),
                        principalAttribute,
                        jaasPrincipal.isUseExistingPrincipalId() || personDirectory.isUseExistingPrincipalId(),
                        jaasPrincipal.isAttributeResolutionEnabled());
                })
                .collect(Collectors.toList());
        }

        @ConditionalOnMissingBean(name = "jaasAuthenticationHandlers")
        @RefreshScope
        @Bean
        public List<AuthenticationHandler> jaasAuthenticationHandlers() {
            return casProperties.getAuthn().getJaas()
                .stream()
                .filter(jaas -> StringUtils.isNotBlank(jaas.getRealm()))
                .map(jaas -> {
                    val h = new JaasAuthenticationHandler(jaas.getName(), servicesManager.getIfAvailable(),
                        jaasPrincipalFactory(), jaas.getOrder());

                    h.setKerberosKdcSystemProperty(jaas.getKerberosKdcSystemProperty());
                    h.setKerberosRealmSystemProperty(jaas.getKerberosRealmSystemProperty());
                    h.setRealm(jaas.getRealm());
                    h.setPasswordEncoder(PasswordEncoderUtils.newPasswordEncoder(jaas.getPasswordEncoder()));

                    if (StringUtils.isNotBlank(jaas.getLoginConfigType())) {
                        h.setLoginConfigType(jaas.getLoginConfigType());
                    }
                    if (StringUtils.isNotBlank(jaas.getLoginConfigurationFile())) {
                        h.setLoginConfigurationFile(new File(jaas.getLoginConfigurationFile()));
                    }
                    val passwordPolicy = jaas.getPasswordPolicy();
                    h.setPasswordPolicyHandlingStrategy(CoreAuthenticationUtils.newPasswordPolicyHandlingStrategy(passwordPolicy));
                    if (passwordPolicy.isEnabled()) {
                        LOGGER.debug("Password policy is enabled for JAAS. Constructing password policy configuration for [{}]", jaas.getRealm());
                        val cfg = new PasswordPolicyConfiguration(passwordPolicy);
                        if (passwordPolicy.isAccountStateHandlingEnabled()) {
                            cfg.setAccountStateHandler((response, configuration) -> new ArrayList<>(0));
                        } else {
                            LOGGER.debug("Handling account states is disabled via CAS configuration");
                        }
                        h.setPasswordPolicyConfiguration(cfg);
                    }
                    h.setPrincipalNameTransformer(PrincipalNameTransformerUtils.newPrincipalNameTransformer(jaas.getPrincipalTransformation()));
                    h.setCredentialSelectionPredicate(CoreAuthenticationUtils.newCredentialSelectionPredicate(jaas.getCredentialCriteria()));
                    return h;
                })
                .collect(Collectors.toList());
        }

        @ConditionalOnMissingBean(name = "jaasAuthenticationEventExecutionPlanConfigurer")
        @Bean
        public AuthenticationEventExecutionPlanConfigurer jaasAuthenticationEventExecutionPlanConfigurer() {
            return plan -> plan.registerAuthenticationHandlerWithPrincipalResolvers(jaasAuthenticationHandlers(), jaasPersonDirectoryPrincipalResolvers());
        }
    }
}
