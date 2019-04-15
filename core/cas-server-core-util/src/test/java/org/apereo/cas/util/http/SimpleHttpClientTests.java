package org.apereo.cas.util.http;

import org.apereo.cas.util.CollectionUtils;

import lombok.SneakyThrows;
import lombok.val;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test cases for {@link SimpleHttpClient}.
 *
 * @author Scott Battaglia
 * @since 3.1
 */
public class SimpleHttpClientTests {

    private static SimpleHttpClient getHttpClient() {
        return new SimpleHttpClientFactoryBean().getObject();
    }

    @SneakyThrows
    private static SSLConnectionSocketFactory getFriendlyToAllSSLSocketFactory() {
        val trm = new X509TrustManager() {
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(final X509Certificate[] certs, final String authType) {
            }

            @Override
            public void checkServerTrusted(final X509Certificate[] certs, final String authType) {
            }
        };
        val sc = SSLContext.getInstance("SSL");
        sc.init(null, new TrustManager[]{trm}, null);
        return new SSLConnectionSocketFactory(sc, new NoopHostnameVerifier());
    }

    @Test
    public void verifyOkayUrl() {
        assertTrue(getHttpClient().isValidEndPoint("http://www.google.com"));
    }

    @Test
    public void verifyBadUrl() {
        assertFalse(getHttpClient().isValidEndPoint("https://www.whateverabc1234.org"));
    }

    @Test
    public void verifyInvalidHttpsUrl() {
        val client = getHttpClient();
        assertFalse(client.isValidEndPoint("https://wrong.host.badssl.com/"));
    }

    @Test
    public void verifyBypassedInvalidHttpsUrl() {
        val clientFactory = new SimpleHttpClientFactoryBean();
        clientFactory.setSslSocketFactory(getFriendlyToAllSSLSocketFactory());
        clientFactory.setHostnameVerifier(new NoopHostnameVerifier());
        clientFactory.setAcceptableCodes(CollectionUtils.wrapList(200, 403));
        val client = clientFactory.getObject();
        assertNotNull(client);
        assertTrue(client.isValidEndPoint("https://wrong.host.badssl.com/"));
    }
}
