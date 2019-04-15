package org.apereo.cas.configuration.model.support.cassandra.ticketregistry;

import org.apereo.cas.configuration.model.core.util.EncryptionRandomizedSigningJwtCryptographyProperties;
import org.apereo.cas.configuration.model.support.cassandra.authentication.BaseCassandraProperties;
import org.apereo.cas.configuration.support.RequiresModule;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * This is {@link CassandraTicketRegistryProperties}.
 *
 * @since 6.1.0
 */
@RequiresModule(name = "cas-server-support-cassandra-ticket-registry")
@Getter
@Setter
public class CassandraTicketRegistryProperties extends BaseCassandraProperties {
    /**
     * Crypto settings for the registry.
     */
    @NestedConfigurationProperty
    private EncryptionRandomizedSigningJwtCryptographyProperties crypto = new EncryptionRandomizedSigningJwtCryptographyProperties();
}

