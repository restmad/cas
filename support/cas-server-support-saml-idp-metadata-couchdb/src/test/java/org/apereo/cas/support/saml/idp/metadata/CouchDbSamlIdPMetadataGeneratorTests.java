package org.apereo.cas.support.saml.idp.metadata;

import org.apereo.cas.config.CasCouchDbCoreConfiguration;
import org.apereo.cas.config.CoreSamlConfiguration;
import org.apereo.cas.config.CouchDbSamlIdPFactoryConfiguration;
import org.apereo.cas.config.CouchDbSamlIdPMetadataConfiguration;
import org.apereo.cas.config.SamlIdPCouchDbRegisteredServiceMetadataConfiguration;
import org.apereo.cas.config.SamlIdPMetadataConfiguration;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.couchdb.core.CouchDbConnectorFactory;
import org.apereo.cas.couchdb.saml.SamlIdPMetadataCouchDbRepository;
import org.apereo.cas.support.saml.idp.metadata.generator.SamlIdPMetadataGenerator;
import org.apereo.cas.support.saml.idp.metadata.locator.SamlIdPMetadataLocator;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * This is {@link CouchDbSamlIdPMetadataGeneratorTests}.
 *
 * @author Timur Duehr
 * @since 6.0.0
 */
@SpringBootTest(classes = {
    CouchDbSamlIdPFactoryConfiguration.class,
    CouchDbSamlIdPMetadataConfiguration.class,
    SamlIdPCouchDbRegisteredServiceMetadataConfiguration.class,
    CasCouchDbCoreConfiguration.class,
    SamlIdPMetadataConfiguration.class,
    RefreshAutoConfiguration.class,
    AopAutoConfiguration.class,
    CoreSamlConfiguration.class
    })
@EnableConfigurationProperties(CasConfigurationProperties.class)
@TestPropertySource(properties = {
    "cas.authn.samlIdp.metadata.couchDb.dbName=saml_generator",
    "cas.authn.samlIdp.metadata.couchDb.idpMetadataEnabled=true",
    "cas.authn.samlIdp.metadata.couchDb.username=cas",
    "cas.authn.samlIdp.metadata.couchdb.password=password"
})
@Tag("CouchDb")
public class CouchDbSamlIdPMetadataGeneratorTests {
    @Autowired
    @Qualifier("samlIdPMetadataGenerator")
    protected SamlIdPMetadataGenerator samlIdPMetadataGenerator;

    @Autowired
    @Qualifier("samlIdPMetadataLocator")
    protected SamlIdPMetadataLocator samlIdPMetadataLocator;

    @Autowired
    @Qualifier("samlMetadataCouchDbFactory")
    private CouchDbConnectorFactory couchDbFactory;

    @Autowired
    @Qualifier("samlIdPMetadataCouchDbRepository")
    private SamlIdPMetadataCouchDbRepository couchDbRepository;

    @BeforeEach
    public void setUp() {
        couchDbFactory.getCouchDbInstance().createDatabaseIfNotExists(couchDbFactory.getCouchDbConnector().getDatabaseName());
        couchDbRepository.initStandardDesignDocument();
    }

    @AfterEach
    public void tearDown() {
        couchDbFactory.getCouchDbInstance().deleteDatabase(couchDbFactory.getCouchDbConnector().getDatabaseName());
    }

    @Test
    public void verifyOperation() {
        this.samlIdPMetadataGenerator.generate();
        assertNotNull(samlIdPMetadataLocator.getMetadata());
        assertNotNull(samlIdPMetadataLocator.getEncryptionCertificate());
        assertNotNull(samlIdPMetadataLocator.getEncryptionKey());
        assertNotNull(samlIdPMetadataLocator.getSigningCertificate());
        assertNotNull(samlIdPMetadataLocator.getSigningKey());
    }
}
