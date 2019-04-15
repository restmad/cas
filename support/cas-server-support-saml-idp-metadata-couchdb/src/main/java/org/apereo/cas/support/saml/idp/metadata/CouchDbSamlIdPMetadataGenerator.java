package org.apereo.cas.support.saml.idp.metadata;

import org.apereo.cas.couchdb.saml.CouchDbSamlIdPMetadataDocument;
import org.apereo.cas.couchdb.saml.SamlIdPMetadataCouchDbRepository;
import org.apereo.cas.support.saml.idp.metadata.generator.BaseSamlIdPMetadataGenerator;
import org.apereo.cas.support.saml.idp.metadata.generator.SamlIdPMetadataGeneratorConfigurationContext;
import org.apereo.cas.support.saml.services.idp.metadata.SamlIdPMetadataDocument;

import lombok.SneakyThrows;
import lombok.val;
import org.apache.commons.lang3.tuple.Pair;

/**
 * This is {@link CouchDbSamlIdPMetadataGenerator}.
 *
 * @author Timur Duehr
 * @since 6.0.0
 */
public class CouchDbSamlIdPMetadataGenerator extends BaseSamlIdPMetadataGenerator {

    private final SamlIdPMetadataCouchDbRepository couchDb;

    public CouchDbSamlIdPMetadataGenerator(final SamlIdPMetadataGeneratorConfigurationContext samlIdPMetadataGeneratorConfigurationContext, final SamlIdPMetadataCouchDbRepository couchDb) {
        super(samlIdPMetadataGeneratorConfigurationContext);
        this.couchDb = couchDb;
    }

    @Override
    @SneakyThrows
    public Pair<String, String> buildSelfSignedEncryptionCert() {
        val results = generateCertificateAndKey();
        val doc = getSamlIdPMetadataDocument();
        doc.setEncryptionCertificate(results.getKey());
        doc.setEncryptionKey(results.getValue());
        saveSamlIdPMetadataDocument(doc);
        return results;
    }

    @Override
    @SneakyThrows
    public Pair<String, String> buildSelfSignedSigningCert() {
        val results = generateCertificateAndKey();
        val doc = getSamlIdPMetadataDocument();
        doc.setSigningCertificate(results.getKey());
        doc.setSigningKey(results.getValue());
        saveSamlIdPMetadataDocument(doc);
        return results;
    }

    @Override
    protected String writeMetadata(final String metadata) {
        val doc = getSamlIdPMetadataDocument();
        doc.setMetadata(metadata);
        saveSamlIdPMetadataDocument(doc);
        return metadata;
    }

    private void saveSamlIdPMetadataDocument(final SamlIdPMetadataDocument doc) {
        val couchDoc = couchDb.getOne();
        if (couchDoc == null) {
            couchDb.add(new CouchDbSamlIdPMetadataDocument(doc));
        } else {
            couchDb.update(couchDoc.merge(doc));
        }
    }

    private CouchDbSamlIdPMetadataDocument getSamlIdPMetadataDocument() {
        val metadata = couchDb.getOne();
        if (metadata == null) {
            return new CouchDbSamlIdPMetadataDocument();
        }
        return metadata;
    }


}
