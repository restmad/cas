package org.apereo.cas.ticket.registry;

import org.apereo.cas.util.junit.EnabledIfContinuousIntegration;

import org.springframework.test.context.TestPropertySource;

/**
 * Unit test for {@link RedisTicketRegistry}.
 *
 * @author Julien Gribonvald
 * @since 6.1.0
 */
@TestPropertySource(properties = {
    "cas.ticket.registry.redis.host=localhost",
    "cas.ticket.registry.redis.port=6379",
    "cas.ticket.registry.redis.readFrom=MASTER",
    "cas.ticket.registry.redis.pool.max-active=20",
    "cas.ticket.registry.redis.sentinel.master=mymaster",
    "cas.ticket.registry.redis.sentinel.node[0]=localhost:26379",
    "cas.ticket.registry.redis.sentinel.node[1]=localhost:26380",
    "cas.ticket.registry.redis.sentinel.node[2]=localhost:26381"
})
@EnabledIfContinuousIntegration
public class SentinelServerTicketRegistryTests extends BaseRedisSentinelTicketRegistryTests {
}
