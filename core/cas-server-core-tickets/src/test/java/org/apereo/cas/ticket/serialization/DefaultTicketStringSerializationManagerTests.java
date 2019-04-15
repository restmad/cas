package org.apereo.cas.ticket.serialization;

import org.apereo.cas.config.CasCoreTicketCatalogConfiguration;
import org.apereo.cas.config.CasCoreTicketsConfiguration;
import org.apereo.cas.config.CasCoreTicketsSerializationConfiguration;
import org.apereo.cas.services.RegisteredServiceTestUtils;
import org.apereo.cas.ticket.TicketFactory;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.TicketGrantingTicketFactory;

import lombok.val;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * This is {@link DefaultTicketStringSerializationManagerTests}.
 *
 * @author Misagh Moayyed
 * @since 6.1.0
 */
@SpringBootTest(classes = {
    RefreshAutoConfiguration.class,
    CasCoreTicketsConfiguration.class,
    CasCoreTicketCatalogConfiguration.class,
    CasCoreTicketsSerializationConfiguration.class
})
public class DefaultTicketStringSerializationManagerTests {
    @Autowired
    @Qualifier("ticketSerializationManager")
    private TicketSerializationManager ticketSerializationManager;

    @Autowired
    @Qualifier("defaultTicketFactory")
    private TicketFactory defaultTicketFactory;

    @Test
    public void verifyOperation() {
        val factory = (TicketGrantingTicketFactory) this.defaultTicketFactory.get(TicketGrantingTicket.class);
        val ticket = factory.create(RegisteredServiceTestUtils.getAuthentication(), TicketGrantingTicket.class);
        val result = ticketSerializationManager.serializeTicket(ticket);
        assertNotNull(result);
        val deserializedTicket = ticketSerializationManager.deserializeTicket(result, TicketGrantingTicket.class);
        assertNotNull(deserializedTicket);
    }
}
