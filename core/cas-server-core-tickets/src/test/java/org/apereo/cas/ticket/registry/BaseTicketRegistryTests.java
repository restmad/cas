package org.apereo.cas.ticket.registry;

import org.apereo.cas.CipherExecutor;
import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.config.CasCoreTicketCatalogConfiguration;
import org.apereo.cas.config.CasCoreTicketsConfiguration;
import org.apereo.cas.config.CasCoreTicketsSerializationConfiguration;
import org.apereo.cas.configuration.model.core.util.EncryptionRandomizedSigningJwtCryptographyProperties;
import org.apereo.cas.services.RegisteredServiceTestUtils;
import org.apereo.cas.ticket.AbstractTicket;
import org.apereo.cas.ticket.ServiceTicket;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.TicketGrantingTicketImpl;
import org.apereo.cas.ticket.TransientSessionTicket;
import org.apereo.cas.ticket.TransientSessionTicketImpl;
import org.apereo.cas.ticket.proxy.ProxyGrantingTicket;
import org.apereo.cas.ticket.support.AlwaysExpiresExpirationPolicy;
import org.apereo.cas.ticket.support.NeverExpiresExpirationPolicy;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.CoreTicketUtils;
import org.apereo.cas.util.DefaultUniqueTicketIdGenerator;
import org.apereo.cas.util.ProxyGrantingTicketIdGenerator;
import org.apereo.cas.util.ServiceTicketIdGenerator;
import org.apereo.cas.util.TicketGrantingTicketIdGenerator;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.util.AopTestUtils;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collections;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

/**
 * This is {@link BaseTicketRegistryTests}.
 *
 * @author Misagh Moayyed
 * @since 5.3.0
 */
@Slf4j
@SpringBootTest(classes = {
    CasCoreTicketsConfiguration.class,
    CasCoreTicketCatalogConfiguration.class,
    CasCoreTicketsSerializationConfiguration.class
})
public abstract class BaseTicketRegistryTests {

    private static final int TICKETS_IN_REGISTRY = 10;
    private static final String TICKET_SHOULD_BE_NULL_USE_ENCRYPTION = "Ticket should be null. useEncryption[";

    protected boolean useEncryption;

    private String ticketGrantingTicketId;
    private String serviceTicketId;
    private String transientSessionTicketId;
    private String proxyGrantingTicketId;

    private TicketRegistry ticketRegistry;

    @BeforeEach
    public void initialize(final RepetitionInfo info) {
        this.ticketGrantingTicketId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
            .getNewTicketId(TicketGrantingTicket.PREFIX);
        this.serviceTicketId = new ServiceTicketIdGenerator(10, StringUtils.EMPTY)
            .getNewTicketId(ServiceTicket.PREFIX);
        this.proxyGrantingTicketId = new ProxyGrantingTicketIdGenerator(10, StringUtils.EMPTY)
            .getNewTicketId(ProxyGrantingTicket.PROXY_GRANTING_TICKET_PREFIX);
        this.transientSessionTicketId = new DefaultUniqueTicketIdGenerator().getNewTicketId(TransientSessionTicket.PREFIX);

        useEncryption = info.getCurrentRepetition() % 2 != 0;

        ticketRegistry = this.getNewTicketRegistry();
        if (ticketRegistry != null) {
            ticketRegistry.deleteAll();
            setUpEncryption();
        }
    }

    protected abstract TicketRegistry getNewTicketRegistry();

    private void setUpEncryption() {
        var registry = (AbstractTicketRegistry) AopTestUtils.getTargetObject(ticketRegistry);
        if (this.useEncryption) {
            val cipher = CoreTicketUtils.newTicketRegistryCipherExecutor(
                new EncryptionRandomizedSigningJwtCryptographyProperties(), "[tests]");
            registry.setCipherExecutor(cipher);
        } else {
            registry.setCipherExecutor(CipherExecutor.noOp());
        }
    }

    /**
     * Determine whether the tested registry is able to iterate its tickets.
     */
    protected boolean isIterableRegistry() {
        return true;
    }

    @RepeatedTest(2)
    public void verifyAddTicketToCache() {
        val originalAuthn = CoreAuthenticationTestUtils.getAuthentication();
        ticketRegistry.addTicket(new TicketGrantingTicketImpl(ticketGrantingTicketId,
            originalAuthn,
            new NeverExpiresExpirationPolicy()));
        val tgt = ticketRegistry.getTicket(ticketGrantingTicketId, TicketGrantingTicket.class);
        assertNotNull(tgt);
        val authentication = tgt.getAuthentication();
        assertNotNull(authentication);
        assertNotNull(authentication.getSuccesses());
        assertNotNull(authentication.getWarnings());
        assertNotNull(authentication.getFailures());
    }

    @RepeatedTest(2)
    public void verifyGetNullTicket() {
        assertNull(ticketRegistry.getTicket(null, TicketGrantingTicket.class), TICKET_SHOULD_BE_NULL_USE_ENCRYPTION + useEncryption + ']');
    }

    @RepeatedTest(2)
    public void verifyGetNonExistingTicket() {
        assertNull(ticketRegistry.getTicket("FALALALALALAL", TicketGrantingTicket.class), TICKET_SHOULD_BE_NULL_USE_ENCRYPTION + useEncryption + ']');
    }

    @RepeatedTest(2)
    public void verifyGetExistingTicketWithProperClass() {
        ticketRegistry.addTicket(new TicketGrantingTicketImpl(ticketGrantingTicketId,
            CoreAuthenticationTestUtils.getAuthentication(),
            new NeverExpiresExpirationPolicy()));
        val ticket = ticketRegistry.getTicket(ticketGrantingTicketId, TicketGrantingTicket.class);
        assertNotNull(ticket, "Ticket is null. useEncryption[" + useEncryption + ']');
        assertEquals(ticketGrantingTicketId, ticket.getId(), "Ticket IDs don't match. useEncryption[" + useEncryption + ']');
    }

    @RepeatedTest(2)
    public void verifyGetExistingTicketWithImproperClass() {
        ticketRegistry.addTicket(new TicketGrantingTicketImpl(ticketGrantingTicketId,
            CoreAuthenticationTestUtils.getAuthentication(),
            new NeverExpiresExpirationPolicy()));

        assertThrows(ClassCastException.class,
            () -> ticketRegistry.getTicket(ticketGrantingTicketId, ServiceTicket.class),
            "Should throw ClassCastException. useEncryption[" + useEncryption + ']');
    }

    @RepeatedTest(2)
    public void verifyGetNullTicketWithoutClass() {
        assertNull(ticketRegistry.getTicket(null), TICKET_SHOULD_BE_NULL_USE_ENCRYPTION + useEncryption + ']');
    }

    @RepeatedTest(2)
    public void verifyGetNonExistingTicketWithoutClass() {
        assertNull(ticketRegistry.getTicket("FALALALALALAL"), TICKET_SHOULD_BE_NULL_USE_ENCRYPTION + useEncryption + ']');
    }

    @RepeatedTest(2)
    public void verifyGetExistingTicket() {
        ticketRegistry.addTicket(new TicketGrantingTicketImpl(ticketGrantingTicketId,
            CoreAuthenticationTestUtils.getAuthentication(),
            new NeverExpiresExpirationPolicy()));
        val ticket = ticketRegistry.getTicket(ticketGrantingTicketId);
        assertNotNull(ticket, "Ticket is null. useEncryption[" + useEncryption + ']');
        assertEquals(ticketGrantingTicketId, ticket.getId(), "Ticket IDs don't match. useEncryption[" + useEncryption + ']');
    }

    @RepeatedTest(2)
    public void verifyAddAndUpdateTicket() {
        TicketGrantingTicket tgt = new TicketGrantingTicketImpl(
            ticketGrantingTicketId,
            CoreAuthenticationTestUtils.getAuthentication(),
            new NeverExpiresExpirationPolicy());
        ticketRegistry.addTicket(tgt);

        tgt = ticketRegistry.getTicket(tgt.getId(), TicketGrantingTicket.class);
        assertNotNull(tgt, "Ticket is null. useEncryption[" + useEncryption + ']');
        assertTrue(tgt.getServices().isEmpty(), "Ticket services should be empty. useEncryption[" + useEncryption + ']');

        tgt.grantServiceTicket("ST1", RegisteredServiceTestUtils.getService("TGT_UPDATE_TEST"),
            new NeverExpiresExpirationPolicy(), false, false);
        ticketRegistry.updateTicket(tgt);

        tgt = ticketRegistry.getTicket(tgt.getId(), TicketGrantingTicket.class);
        assertEquals(Collections.singleton("ST1"), tgt.getServices().keySet());
    }

    @RepeatedTest(2)
    public void verifyDeleteAllExistingTickets() {
        assumeTrue(isIterableRegistry());
        for (var i = 0; i < TICKETS_IN_REGISTRY; i++) {
            ticketRegistry.addTicket(new TicketGrantingTicketImpl(ticketGrantingTicketId + i,
                CoreAuthenticationTestUtils.getAuthentication(),
                new NeverExpiresExpirationPolicy()));
        }
        val actual = ticketRegistry.deleteAll();
        assertEquals(TICKETS_IN_REGISTRY, actual, "Wrong ticket count. useEncryption[" + useEncryption + ']');
    }

    @RepeatedTest(2)
    @Transactional
    public void verifyDeleteExistingTicket() {
        ticketRegistry.addTicket(new TicketGrantingTicketImpl(ticketGrantingTicketId,
            CoreAuthenticationTestUtils.getAuthentication(),
            new NeverExpiresExpirationPolicy()));
        assertSame(1, ticketRegistry.deleteTicket(ticketGrantingTicketId), "Wrong ticket count. useEncryption[" + useEncryption + ']');
        assertNull(ticketRegistry.getTicket(ticketGrantingTicketId), TICKET_SHOULD_BE_NULL_USE_ENCRYPTION + useEncryption + ']');
    }

    @RepeatedTest(2)
    @Transactional
    public void verifyTransientSessionTickets() {
        ticketRegistry.addTicket(new TransientSessionTicketImpl(transientSessionTicketId, new NeverExpiresExpirationPolicy(),
            RegisteredServiceTestUtils.getService(), CollectionUtils.wrap("key", "value")));
        assertSame(1, ticketRegistry.deleteTicket(transientSessionTicketId), "Wrong ticket count. useEncryption[" + useEncryption + ']');
        assertNull(ticketRegistry.getTicket(transientSessionTicketId), TICKET_SHOULD_BE_NULL_USE_ENCRYPTION + useEncryption + ']');
    }

    @RepeatedTest(2)
    @Transactional
    public void verifyDeleteNonExistingTicket() {
        ticketRegistry.addTicket(new TicketGrantingTicketImpl(ticketGrantingTicketId,
            CoreAuthenticationTestUtils.getAuthentication(),
            new NeverExpiresExpirationPolicy()));
        assertSame(0, ticketRegistry.deleteTicket(ticketGrantingTicketId + "NON-EXISTING-SUFFIX"));
    }

    @RepeatedTest(2)
    public void verifyDeleteNullTicket() {
        ticketRegistry.addTicket(new TicketGrantingTicketImpl(ticketGrantingTicketId,
            CoreAuthenticationTestUtils.getAuthentication(),
            new NeverExpiresExpirationPolicy()));
        assertNotEquals(1, ticketRegistry.deleteTicket(StringUtils.EMPTY), "Ticket was deleted.");
    }

    @RepeatedTest(2)
    public void verifyGetTicketsIsZero() {
        ticketRegistry.deleteAll();
        assertEquals(0, ticketRegistry.getTickets().size(), "The size of the empty registry is not zero.");
    }

    @RepeatedTest(2)
    public void verifyGetTicketsFromRegistryEqualToTicketsAdded() {
        assumeTrue(isIterableRegistry());
        val tickets = new ArrayList<Ticket>();

        for (var i = 0; i < TICKETS_IN_REGISTRY; i++) {
            val ticketGrantingTicket = new TicketGrantingTicketImpl(ticketGrantingTicketId + i,
                CoreAuthenticationTestUtils.getAuthentication(), new NeverExpiresExpirationPolicy());
            val st = ticketGrantingTicket.grantServiceTicket("ST" + i,
                RegisteredServiceTestUtils.getService(),
                new NeverExpiresExpirationPolicy(), false, true);
            tickets.add(ticketGrantingTicket);
            tickets.add(st);
            ticketRegistry.addTicket(ticketGrantingTicket);
            ticketRegistry.addTicket(st);
        }

        val ticketRegistryTickets = ticketRegistry.getTickets();
        assertEquals(tickets.size(), ticketRegistryTickets.size(), "The size of the registry is not the same as the collection.");


        tickets.stream().filter(ticket -> !ticketRegistryTickets.contains(ticket))
            .forEach(ticket -> {
                throw new AssertionError("Ticket " + ticket + " was not found in retrieval of collection of all tickets.");
            });
    }

    @RepeatedTest(2)
    @Transactional
    public void verifyDeleteTicketWithChildren() {
        ticketRegistry.addTicket(new TicketGrantingTicketImpl(ticketGrantingTicketId + '1', CoreAuthenticationTestUtils.getAuthentication(),
            new NeverExpiresExpirationPolicy()));
        val tgt = ticketRegistry.getTicket(ticketGrantingTicketId + '1', TicketGrantingTicket.class);

        val service = RegisteredServiceTestUtils.getService("TGT_DELETE_TEST");

        val st1 = tgt.grantServiceTicket("ST11", service, new NeverExpiresExpirationPolicy(), false, false);
        val st2 = tgt.grantServiceTicket("ST21", service, new NeverExpiresExpirationPolicy(), false, false);
        val st3 = tgt.grantServiceTicket("ST31", service, new NeverExpiresExpirationPolicy(), false, false);

        ticketRegistry.addTicket(st1);
        ticketRegistry.addTicket(st2);
        ticketRegistry.addTicket(st3);

        assertNotNull(ticketRegistry.getTicket(ticketGrantingTicketId + '1', TicketGrantingTicket.class));
        assertNotNull(ticketRegistry.getTicket("ST11", ServiceTicket.class));
        assertNotNull(ticketRegistry.getTicket("ST21", ServiceTicket.class));
        assertNotNull(ticketRegistry.getTicket("ST31", ServiceTicket.class));

        ticketRegistry.updateTicket(tgt);
        assertSame(4, ticketRegistry.deleteTicket(tgt.getId()));

        assertNull(ticketRegistry.getTicket(ticketGrantingTicketId + '1', TicketGrantingTicket.class));
        assertNull(ticketRegistry.getTicket("ST11", ServiceTicket.class));
        assertNull(ticketRegistry.getTicket("ST21", ServiceTicket.class));
        assertNull(ticketRegistry.getTicket("ST31", ServiceTicket.class));
    }

    @RepeatedTest(2)
    @Transactional
    public void verifyWriteGetDelete() {
        val ticket = new TicketGrantingTicketImpl(ticketGrantingTicketId,
            CoreAuthenticationTestUtils.getAuthentication(),
            new NeverExpiresExpirationPolicy());
        ticketRegistry.addTicket(ticket);
        val ticketFromRegistry = ticketRegistry.getTicket(ticketGrantingTicketId);
        assertNotNull(ticketFromRegistry);
        assertEquals(ticketGrantingTicketId, ticketFromRegistry.getId());
        ticketRegistry.deleteTicket(ticketGrantingTicketId);
        assertNull(ticketRegistry.getTicket(ticketGrantingTicketId));
    }

    @RepeatedTest(2)
    public void verifyExpiration() {
        val authn = CoreAuthenticationTestUtils.getAuthentication();
        LOGGER.trace("Adding ticket [{}]", ticketGrantingTicketId);
        ticketRegistry.addTicket(new TicketGrantingTicketImpl(ticketGrantingTicketId, authn, new NeverExpiresExpirationPolicy()));
        LOGGER.trace("Getting ticket [{}]", ticketGrantingTicketId);
        val tgt = ticketRegistry.getTicket(ticketGrantingTicketId, TicketGrantingTicket.class);
        assertNotNull(tgt, "Ticket-granting ticket " + ticketGrantingTicketId + " cannot be fetched");
        val service = RegisteredServiceTestUtils.getService("TGT_DELETE_TEST");
        LOGGER.trace("Granting service ticket [{}]", serviceTicketId);
        val ticket = (AbstractTicket) tgt.grantServiceTicket(serviceTicketId, service,
            new NeverExpiresExpirationPolicy(), false, true);
        assertNotNull(ticket, "Service ticket cannot be null");
        ticket.setExpirationPolicy(new AlwaysExpiresExpirationPolicy());
        ticketRegistry.addTicket(ticket);
        ticketRegistry.updateTicket(tgt);
        assertNull(ticketRegistry.getTicket(serviceTicketId, ServiceTicket.class));
    }

    @RepeatedTest(2)
    public void verifyExpiredTicket() {
        val authn = CoreAuthenticationTestUtils.getAuthentication();
        ticketRegistry.addTicket(new TicketGrantingTicketImpl(ticketGrantingTicketId, authn, new AlwaysExpiresExpirationPolicy()));
        var tgt = ticketRegistry.getTicket(ticketGrantingTicketId, TicketGrantingTicket.class);
        assertNull(tgt);
    }


    @RepeatedTest(2)
    @Transactional
    public void verifyDeleteTicketWithPGT() {
        val a = CoreAuthenticationTestUtils.getAuthentication();
        ticketRegistry.addTicket(new TicketGrantingTicketImpl(ticketGrantingTicketId, a, new NeverExpiresExpirationPolicy()));
        val tgt = ticketRegistry.getTicket(ticketGrantingTicketId, TicketGrantingTicket.class);

        val service = RegisteredServiceTestUtils.getService("TGT_DELETE_TEST");

        val st1 = tgt.grantServiceTicket(serviceTicketId, service, new NeverExpiresExpirationPolicy(), false, true);
        ticketRegistry.addTicket(st1);
        ticketRegistry.updateTicket(tgt);

        assertNotNull(ticketRegistry.getTicket(ticketGrantingTicketId, TicketGrantingTicket.class));
        assertNotNull(ticketRegistry.getTicket(serviceTicketId, ServiceTicket.class));

        val pgt = st1.grantProxyGrantingTicket(proxyGrantingTicketId, a, new NeverExpiresExpirationPolicy());
        ticketRegistry.addTicket(pgt);
        ticketRegistry.updateTicket(tgt);
        ticketRegistry.updateTicket(st1);
        assertEquals(pgt.getTicketGrantingTicket(), tgt);
        assertNotNull(ticketRegistry.getTicket(proxyGrantingTicketId, ProxyGrantingTicket.class));
        assertEquals(a, pgt.getAuthentication());
        assertNotNull(ticketRegistry.getTicket(serviceTicketId, ServiceTicket.class));

        assertTrue(ticketRegistry.deleteTicket(tgt.getId()) > 0);

        assertNull(ticketRegistry.getTicket(ticketGrantingTicketId, TicketGrantingTicket.class));
        assertNull(ticketRegistry.getTicket(serviceTicketId, ServiceTicket.class));
        assertNull(ticketRegistry.getTicket(proxyGrantingTicketId, ProxyGrantingTicket.class));
    }

    @RepeatedTest(2)
    @Transactional
    public void verifyDeleteTicketsWithMultiplePGTs() {
        val a = CoreAuthenticationTestUtils.getAuthentication();
        ticketRegistry.addTicket(new TicketGrantingTicketImpl(ticketGrantingTicketId, a, new NeverExpiresExpirationPolicy()));
        val tgt = ticketRegistry.getTicket(ticketGrantingTicketId, TicketGrantingTicket.class);
        assertNotNull(tgt, "Ticket-granting ticket must not be null");
        val service = RegisteredServiceTestUtils.getService("TGT_DELETE_TEST");
        IntStream.range(1, 5).forEach(i -> {
            val st = tgt.grantServiceTicket(serviceTicketId + '-' + i, service,
                new NeverExpiresExpirationPolicy(), false, true);
            ticketRegistry.addTicket(st);
            ticketRegistry.updateTicket(tgt);

            val pgt = st.grantProxyGrantingTicket(proxyGrantingTicketId + '-' + i, a, new NeverExpiresExpirationPolicy());
            ticketRegistry.addTicket(pgt);
            ticketRegistry.updateTicket(tgt);
            ticketRegistry.updateTicket(st);
        });

        val c = ticketRegistry.deleteTicket(ticketGrantingTicketId);
        assertEquals(6, c);
    }
}
