package org.apereo.cas.ticket.registry;

import org.apereo.cas.ComponentSerializationPlan;
import org.apereo.cas.ComponentSerializationPlanConfigurator;
import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.config.CasCoreTicketCatalogConfiguration;
import org.apereo.cas.config.CasCoreTicketsConfiguration;
import org.apereo.cas.config.CasCoreUtilSerializationConfiguration;
import org.apereo.cas.config.CasOAuthComponentSerializationConfiguration;
import org.apereo.cas.config.MemcachedTicketRegistryConfiguration;
import org.apereo.cas.mock.MockServiceTicket;
import org.apereo.cas.mock.MockTicketGrantingTicket;
import org.apereo.cas.services.RegisteredServiceTestUtils;
import org.apereo.cas.ticket.code.DefaultOAuthCodeFactory;
import org.apereo.cas.ticket.code.OAuthCode;
import org.apereo.cas.ticket.support.NeverExpiresExpirationPolicy;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.junit.EnabledIfContinuousIntegration;

import lombok.val;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit test for MemcachedTicketRegistry class.
 *
 * @author Middleware Services
 * @since 3.0.0
 */
@SpringBootTest(classes = {
    MemcachedTicketRegistryConfiguration.class,
    CasOAuthComponentSerializationConfiguration.class,
    MemcachedTicketRegistryTests.MemcachedTicketRegistryTestConfiguration.class,
    RefreshAutoConfiguration.class,
    CasCoreUtilSerializationConfiguration.class,
    CasCoreTicketsConfiguration.class,
    CasCoreTicketCatalogConfiguration.class
})
@TestPropertySource(properties = {
    "cas.ticket.registry.memcached.servers=localhost:11211",
    "cas.ticket.registry.memcached.failureMode=Redistribute",
    "cas.ticket.registry.memcached.locatorType=ARRAY_MOD",
    "cas.ticket.registry.memcached.hashAlgorithm=FNV1A_64_HASH",
    "cas.ticket.registry.memcached.kryoRegistrationRequired=true"
})
@EnabledIfContinuousIntegration
@Tag("Memcached")
public class MemcachedTicketRegistryTests extends BaseTicketRegistryTests {
    @Autowired
    @Qualifier("ticketRegistry")
    private TicketRegistry registry;

    @Override
    public TicketRegistry getNewTicketRegistry() {
        return registry;
    }

    @Override
    protected boolean isIterableRegistry() {
        return false;
    }

    @RepeatedTest(2)
    public void verifyOAuthCodeIsAddedToMemcached() {
        val factory = new DefaultOAuthCodeFactory(new NeverExpiresExpirationPolicy());
        val code = factory.create(RegisteredServiceTestUtils.getService(), CoreAuthenticationTestUtils.getAuthentication(),
            new MockTicketGrantingTicket("casuser"), CollectionUtils.wrapList("openid"),
            "code-challenge", "plain");
        this.registry.addTicket(code);
        val ticket = this.registry.getTicket(code.getId(), OAuthCode.class);
        assertNotNull(ticket);
    }

    @TestConfiguration
    public static class MemcachedTicketRegistryTestConfiguration implements ComponentSerializationPlanConfigurator {
        @Override
        public void configureComponentSerializationPlan(final ComponentSerializationPlan plan) {
            plan.registerSerializableClass(MockTicketGrantingTicket.class);
            plan.registerSerializableClass(MockServiceTicket.class);
        }
    }
}
