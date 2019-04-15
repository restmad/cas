package org.apereo.cas.services;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

/**
 * This is {@link DefaultRegisteredServiceProxyTicketExpirationPolicy}.
 *
 * @author Misagh Moayyed
 * @since 6.1.0
 */
@Slf4j
@Getter
@Setter
@EqualsAndHashCode
@AllArgsConstructor
@NoArgsConstructor
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@ToString
public class DefaultRegisteredServiceProxyTicketExpirationPolicy implements RegisteredServiceProxyTicketExpirationPolicy {
    private static final long serialVersionUID = -4125109870746310448L;

    private long numberOfUses;

    private long timeToLive;
}
