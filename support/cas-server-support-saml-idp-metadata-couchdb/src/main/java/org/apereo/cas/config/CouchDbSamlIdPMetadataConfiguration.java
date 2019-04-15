package org.apereo.cas.config;

import org.apereo.cas.CipherExecutor;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.couchdb.core.CouchDbConnectorFactory;
import org.apereo.cas.couchdb.saml.SamlIdPMetadataCouchDbRepository;
import org.apereo.cas.support.saml.idp.metadata.CouchDbSamlIdPMetadataCipherExecutor;
import org.apereo.cas.support.saml.idp.metadata.CouchDbSamlIdPMetadataGenerator;
import org.apereo.cas.support.saml.idp.metadata.CouchDbSamlIdPMetadataLocator;
import org.apereo.cas.support.saml.idp.metadata.generator.SamlIdPMetadataGenerator;
import org.apereo.cas.support.saml.idp.metadata.generator.SamlIdPMetadataGeneratorConfigurationContext;
import org.apereo.cas.support.saml.idp.metadata.locator.SamlIdPMetadataLocator;
import org.apereo.cas.support.saml.idp.metadata.writer.SamlIdPCertificateAndKeyWriter;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.ektorp.CouchDbConnector;
import org.ektorp.CouchDbInstance;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;

/**
 * This is {@link CouchDbSamlIdPMetadataConfiguration}.
 *
 * @author Timur Duehr
 * @since 6.0.0
 */
@Configuration("ouchDbSamlIdPMetadataConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
@Slf4j
@ConditionalOnProperty(prefix = "cas.authn.samlIdp.metadata.couchDb", name = "idpMetadataEnabled", havingValue = "true")
public class CouchDbSamlIdPMetadataConfiguration {
    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("samlSelfSignedCertificateWriter")
    private ObjectProvider<SamlIdPCertificateAndKeyWriter> samlSelfSignedCertificateWriter;

    @Autowired
    private ResourceLoader resourceLoader;

    @Autowired
    @Qualifier("samlMetadataCouchDbFactory")
    private ObjectProvider<CouchDbConnectorFactory> samlMetadataCouchDbFactory;

    @Autowired
    @Qualifier("samlIdPMetadataCouchDbRepository")
    private ObjectProvider<SamlIdPMetadataCouchDbRepository> samlIdPMetadataRepository;

    @ConditionalOnMissingBean(name = "samlIdPMetadataCouchDbInstance")
    @RefreshScope
    @Bean
    public CouchDbInstance samlIdPMetadataCouchDbInstance() {
        return samlMetadataCouchDbFactory.getIfAvailable().getCouchDbInstance();
    }

    @ConditionalOnMissingBean(name = "samlIdPMetadataCouchDbConnector")
    @RefreshScope
    @Bean
    public CouchDbConnector samlIdPMetadataCouchDbConnector() {
        return samlMetadataCouchDbFactory.getIfAvailable().getCouchDbConnector();
    }

    @ConditionalOnMissingBean(name = "samlIdPMetadataCouchDbRepository")
    @Bean
    @RefreshScope
    public SamlIdPMetadataCouchDbRepository samlIdPMetadataCouchDbRepository() {
        val repository = new SamlIdPMetadataCouchDbRepository(samlMetadataCouchDbFactory.getIfAvailable().getCouchDbConnector(),
            casProperties.getAuthn().getSamlIdp().getMetadata().getCouchDb().isCreateIfNotExists());
        repository.initStandardDesignDocument();
        return repository;
    }

    @Bean
    @RefreshScope
    @ConditionalOnMissingBean(name = "couchDbSamlIdPMetadataCipherExecutor")
    public CipherExecutor couchDbSamlIdPMetadataCipherExecutor() {
        val idp = casProperties.getAuthn().getSamlIdp();
        val crypto = idp.getMetadata().getCouchDb().getCrypto();

        if (crypto.isEnabled()) {
            return new CouchDbSamlIdPMetadataCipherExecutor(
                crypto.getEncryption().getKey(),
                crypto.getSigning().getKey(),
                crypto.getAlg(),
                crypto.getSigning().getKeySize(),
                crypto.getEncryption().getKeySize());
        }
        LOGGER.info("CouchDb SAML IdP metadata encryption/signing is turned off and "
            + "MAY NOT be safe in a production environment. "
            + "Consider using other choices to handle encryption, signing and verification of metadata artifacts");
        return CipherExecutor.noOp();
    }

    @ConditionalOnMissingBean(name = "couchDbSamlIdPMetadataGenerator")
    @Bean(initMethod = "generate")
    public SamlIdPMetadataGenerator samlIdPMetadataGenerator() {
        val idp = casProperties.getAuthn().getSamlIdp();

        val context = SamlIdPMetadataGeneratorConfigurationContext.builder()
            .samlIdPMetadataLocator(samlIdPMetadataLocator())
            .samlIdPCertificateAndKeyWriter(samlSelfSignedCertificateWriter.getIfAvailable())
            .entityId(idp.getEntityId())
            .resourceLoader(resourceLoader)
            .casServerPrefix(casProperties.getServer().getPrefix())
            .scope(idp.getScope())
            .metadataCipherExecutor(couchDbSamlIdPMetadataCipherExecutor())
            .build();

        return new CouchDbSamlIdPMetadataGenerator(context, samlIdPMetadataRepository.getIfAvailable());
    }

    @ConditionalOnMissingBean(name = "couchDbSamlIdPMetadataLocator")
    @Bean
    @SneakyThrows
    public SamlIdPMetadataLocator samlIdPMetadataLocator() {
        return new CouchDbSamlIdPMetadataLocator(couchDbSamlIdPMetadataCipherExecutor(), samlIdPMetadataRepository.getIfAvailable());
    }
}
