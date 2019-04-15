package org.apereo.cas.authentication.metadata;

import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.CredentialMetaData;
import org.apereo.cas.util.serialization.SerializationUtils;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Basic credential metadata implementation that stores the original credential ID and the original credential type.
 * This can be used as a simple converter for any {@link Credential} that doesn't implement {@link CredentialMetaData}.
 *
 * @author Marvin S. Addison
 * @since 4.0.0
 */
@Getter
@NoArgsConstructor(force = true)
@EqualsAndHashCode
@Slf4j
public class BasicCredentialMetaData implements CredentialMetaData {

    /**
     * Serialization version marker.
     */
    private static final long serialVersionUID = 4929579849241505377L;

    /**
     * Credential type unique identifier.
     */
    private final String id;

    /**
     * Type of original credential.
     */
    private final Class<? extends Credential> credentialClass;

    private byte[] credentialInstance;

    /**
     * Creates a new instance from the given credential.
     *
     * @param credential Credential for which metadata should be created.
     */
    public BasicCredentialMetaData(final Credential credential) {
        this.id = credential.getId();
        this.credentialClass = credential.getClass();
        try {
            this.credentialInstance = SerializationUtils.serialize(credential);
        } catch (final Exception e) {
            throw new IllegalArgumentException("Unable to accept/serialize credential " + credentialClass + " to build credential metadata instance.");
        }
    }

    @JsonIgnore
    @Override
    public Credential toCredential() {
        if (credentialInstance != null) {
            return SerializationUtils.deserialize(this.credentialInstance, credentialClass);
        }
        throw new IllegalArgumentException("Unable to accept credential " + credentialClass + " to build credential metadata instance.");
    }
}
