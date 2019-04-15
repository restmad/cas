package org.apereo.cas.services;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This is {@link RestfulServiceRegistry}.
 *
 * @author Misagh Moayyed
 * @since 5.2.0
 */
@Slf4j
public class RestfulServiceRegistry extends AbstractServiceRegistry {
    private final transient RestTemplate restTemplate;
    private final String url;
    private final MultiValueMap<String, String> headers;

    public RestfulServiceRegistry(final ApplicationEventPublisher eventPublisher,
                                  final RestTemplate restTemplate, final String url,
                                  final MultiValueMap<String, String> headers) {
        super(eventPublisher);
        this.restTemplate = restTemplate;
        this.url = url;
        this.headers = headers;
    }

    @Override
    public RegisteredService save(final RegisteredService registeredService) {
        try {
            val requestEntity = new HttpEntity<RegisteredService>(registeredService, this.headers);
            val responseEntity = restTemplate.exchange(this.url, HttpMethod.POST, requestEntity, RegisteredService.class);
            if (responseEntity.getStatusCode().is2xxSuccessful()) {
                return responseEntity.getBody();
            }
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }

    @Override
    public boolean delete(final RegisteredService registeredService) {
        val responseEntity = restTemplate.exchange(this.url, HttpMethod.DELETE,
            new HttpEntity<>(registeredService, this.headers), Integer.class);
        return responseEntity.getStatusCode().is2xxSuccessful();
    }

    @Override
    public Collection<RegisteredService> load() {
        val responseEntity = restTemplate.exchange(this.url, HttpMethod.GET,
            new HttpEntity<>(this.headers), RegisteredService[].class);
        if (responseEntity.getStatusCode().is2xxSuccessful()) {
            val results = responseEntity.getBody();
            return results != null
                ? Stream.of(results).collect(Collectors.toList())
                : new ArrayList<>(0);
        }
        return new ArrayList<>(0);
    }

    @Override
    public RegisteredService findServiceById(final long id) {
        val completeUrl = StringUtils.appendIfMissing(this.url, "/").concat(String.valueOf(id));
        val responseEntity = restTemplate.exchange(completeUrl, HttpMethod.GET,
            new HttpEntity<>(id, this.headers), RegisteredService.class);
        if (responseEntity.getStatusCode().is2xxSuccessful()) {
            return responseEntity.getBody();
        }
        return null;
    }

    @Override
    public RegisteredService findServiceById(final String id) {
        val completeUrl = StringUtils.appendIfMissing(this.url, "/").concat(String.valueOf(id));
        val responseEntity = restTemplate.exchange(completeUrl, HttpMethod.GET,
            new HttpEntity<>(id, this.headers), RegisteredService.class);
        if (responseEntity.getStatusCode().is2xxSuccessful()) {
            return responseEntity.getBody();
        }
        return null;
    }

    @Override
    public long size() {
        return load().size();
    }
}
