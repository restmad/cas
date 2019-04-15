package org.apereo.cas.support.saml.idp.metadata.generator;

import lombok.SneakyThrows;
import lombok.val;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * A metadata generator based on a predefined template.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
public class FileSystemSamlIdPMetadataGenerator extends BaseSamlIdPMetadataGenerator {
    public FileSystemSamlIdPMetadataGenerator(final SamlIdPMetadataGeneratorConfigurationContext samlIdPMetadataGeneratorConfigurationContext) {
        super(samlIdPMetadataGeneratorConfigurationContext);
    }

    @Override
    @SneakyThrows
    public Pair<String, String> buildSelfSignedEncryptionCert() {
        val encCert = getSamlIdPMetadataGeneratorConfigurationContext().getSamlIdPMetadataLocator()
            .getEncryptionCertificate().getFile();
        val encKey = getSamlIdPMetadataGeneratorConfigurationContext().getSamlIdPMetadataLocator()
            .getEncryptionKey().getFile();
        writeCertificateAndKey(encCert, encKey);
        return Pair.of(FileUtils.readFileToString(encCert, StandardCharsets.UTF_8), FileUtils.readFileToString(encKey, StandardCharsets.UTF_8));
    }

    @Override
    @SneakyThrows
    public Pair<String, String> buildSelfSignedSigningCert() {
        val signingCert = getSamlIdPMetadataGeneratorConfigurationContext().getSamlIdPMetadataLocator()
            .getSigningCertificate().getFile();
        val signingKey = getSamlIdPMetadataGeneratorConfigurationContext().getSamlIdPMetadataLocator()
            .getSigningKey().getFile();
        writeCertificateAndKey(signingCert, signingKey);
        return Pair.of(FileUtils.readFileToString(signingCert, StandardCharsets.UTF_8),
            FileUtils.readFileToString(signingKey, StandardCharsets.UTF_8));
    }

    @Override
    @SneakyThrows
    protected String writeMetadata(final String metadata) {
        FileUtils.write(getSamlIdPMetadataGeneratorConfigurationContext().getSamlIdPMetadataLocator()
            .getMetadata().getFile(), metadata, StandardCharsets.UTF_8);
        return metadata;
    }

    @SneakyThrows
    private void writeCertificateAndKey(final File certificate, final File key) {
        if (certificate.exists()) {
            FileUtils.forceDelete(certificate);
        }
        if (key.exists()) {
            FileUtils.forceDelete(key);
        }
        try (val keyWriter = Files.newBufferedWriter(key.toPath(), StandardCharsets.UTF_8);
             val certWriter = Files.newBufferedWriter(certificate.toPath(), StandardCharsets.UTF_8)) {
            getSamlIdPMetadataGeneratorConfigurationContext().getSamlIdPCertificateAndKeyWriter()
                .writeCertificateAndKey(keyWriter, certWriter);
        }
    }

    /**
     * Initializes a new Generate saml metadata.
     */
    @SneakyThrows
    public void initialize() {
        getSamlIdPMetadataGeneratorConfigurationContext().getSamlIdPMetadataLocator().initialize();
        generate();
    }
}
