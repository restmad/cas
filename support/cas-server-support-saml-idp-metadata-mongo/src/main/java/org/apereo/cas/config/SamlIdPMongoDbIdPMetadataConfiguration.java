package org.apereo.cas.config;

import org.apereo.cas.CipherExecutor;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.mongo.MongoDbConnectionFactory;
import org.apereo.cas.support.saml.idp.metadata.MongoDbSamlIdPMetadataCipherExecutor;
import org.apereo.cas.support.saml.idp.metadata.MongoDbSamlIdPMetadataGenerator;
import org.apereo.cas.support.saml.idp.metadata.MongoDbSamlIdPMetadataLocator;
import org.apereo.cas.support.saml.idp.metadata.generator.SamlIdPMetadataGenerator;
import org.apereo.cas.support.saml.idp.metadata.generator.SamlIdPMetadataGeneratorConfigurationContext;
import org.apereo.cas.support.saml.idp.metadata.locator.SamlIdPMetadataLocator;
import org.apereo.cas.support.saml.idp.metadata.writer.SamlIdPCertificateAndKeyWriter;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.data.mongodb.core.MongoTemplate;

/**
 * This is {@link SamlIdPMongoDbIdPMetadataConfiguration}.
 *
 * @author Misagh Moayyed
 * @since 5.2.0
 */
@Configuration("samlIdPMongoDbIdPMetadataConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
@ConditionalOnProperty(prefix = "cas.authn.samlIdp.metadata.mongo", name = "idpMetadataCollection")
@Slf4j
public class SamlIdPMongoDbIdPMetadataConfiguration {

    @Autowired
    private ResourceLoader resourceLoader;

    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("samlSelfSignedCertificateWriter")
    private ObjectProvider<SamlIdPCertificateAndKeyWriter> samlSelfSignedCertificateWriter;

    @Bean
    @ConditionalOnMissingBean(name = "mongoDbSamlIdPMetadataCipherExecutor")
    public CipherExecutor mongoDbSamlIdPMetadataCipherExecutor() {
        val idp = casProperties.getAuthn().getSamlIdp();
        val crypto = idp.getMetadata().getMongo().getCrypto();

        if (crypto.isEnabled()) {
            return new MongoDbSamlIdPMetadataCipherExecutor(
                crypto.getEncryption().getKey(),
                crypto.getSigning().getKey(),
                crypto.getAlg(),
                crypto.getSigning().getKeySize(),
                crypto.getEncryption().getKeySize());
        }
        LOGGER.info("MongoDb SAML IdP metadata encryption/signing is turned off and "
            + "MAY NOT be safe in a production environment. "
            + "Consider using other choices to handle encryption, signing and verification of "
            + "metadata artifacts");
        return CipherExecutor.noOp();
    }

    @ConditionalOnMissingBean(name = "mongoDbSamlIdPMetadataTemplate")
    @Bean
    public MongoTemplate mongoDbSamlIdPMetadataTemplate() {
        val idp = casProperties.getAuthn().getSamlIdp();
        val mongo = idp.getMetadata().getMongo();
        val factory = new MongoDbConnectionFactory();
        val mongoTemplate = factory.buildMongoTemplate(mongo);
        factory.createCollection(mongoTemplate, mongo.getIdpMetadataCollection(), mongo.isDropCollection());
        return mongoTemplate;
    }

    @Bean(initMethod = "generate")
    @SneakyThrows
    public SamlIdPMetadataGenerator samlIdPMetadataGenerator() {
        val idp = casProperties.getAuthn().getSamlIdp();
        val context = SamlIdPMetadataGeneratorConfigurationContext.builder()
            .samlIdPMetadataLocator(samlIdPMetadataLocator())
            .samlIdPCertificateAndKeyWriter(samlSelfSignedCertificateWriter.getIfAvailable())
            .entityId(idp.getEntityId())
            .resourceLoader(resourceLoader)
            .casServerPrefix(casProperties.getServer().getPrefix())
            .scope(idp.getScope())
            .metadataCipherExecutor(mongoDbSamlIdPMetadataCipherExecutor())
            .build();
        return new MongoDbSamlIdPMetadataGenerator(context, mongoDbSamlIdPMetadataTemplate(),
            idp.getMetadata().getMongo().getIdpMetadataCollection());
    }

    @Bean
    @SneakyThrows
    public SamlIdPMetadataLocator samlIdPMetadataLocator() {
        val idp = casProperties.getAuthn().getSamlIdp();
        return new MongoDbSamlIdPMetadataLocator(
            mongoDbSamlIdPMetadataCipherExecutor(),
            mongoDbSamlIdPMetadataTemplate(),
            idp.getMetadata().getMongo().getIdpMetadataCollection());
    }
}
