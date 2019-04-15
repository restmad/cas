package org.apereo.cas.ticket.registry;

import org.apereo.cas.config.CasCoreTicketCatalogConfiguration;
import org.apereo.cas.config.CasCoreTicketsConfiguration;
import org.apereo.cas.config.CasCoreWebConfiguration;
import org.apereo.cas.config.RedisTicketRegistryConfiguration;
import org.apereo.cas.config.support.CasWebApplicationServiceFactoryConfiguration;

import org.junit.jupiter.api.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Common class of Unit test for {@link RedisTicketRegistry} class.
 *
 * @author Julien Gribonvald
 * @since 6.1.0
 */
@Tag("Redis")
@SpringBootTest(classes = {
        RedisTicketRegistryConfiguration.class,
        RefreshAutoConfiguration.class,
        CasCoreWebConfiguration.class,
        AopAutoConfiguration.class,
        CasCoreTicketsConfiguration.class,
        CasCoreTicketCatalogConfiguration.class,
        CasWebApplicationServiceFactoryConfiguration.class})
@EnableTransactionManagement(proxyTargetClass = true)
@EnableAspectJAutoProxy(proxyTargetClass = true)
public abstract class BaseRedisSentinelTicketRegistryTests extends BaseTicketRegistryTests {
    @Autowired
    @Qualifier("ticketRegistry")
    private TicketRegistry ticketRegistry;

    @Override
    public TicketRegistry getNewTicketRegistry() {
        return this.ticketRegistry;
    }
}
