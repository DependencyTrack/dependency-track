package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.dependencytrack.resources.v1.vo.BannerConfig;

public class BannerResourceTest extends ResourceTest {
    @RegisterExtension
    public static JerseyTestExtension jersey = new JerseyTestExtension(
            () -> new ResourceConfig(BannerResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @Test
    void getBannerConfigurationForPresetActive() {
        BannerConfig bannerConfiguration = new BannerConfig();
        bannerConfiguration.activateBanner = true;
        bannerConfiguration.customMode = false;
        bannerConfiguration.message = "Banner Test Preset";
        qm.setBannerConfig(bannerConfiguration);

        Response response = jersey.target("/v1/banner").request().header(X_API_KEY, apiKey).get();
        assertEquals(200, response.getStatus());
        JsonObject bannerJson = parseJsonObject(response);
        assertEquals(true, bannerJson.getBoolean("activateBanner"));
        assertEquals(false, bannerJson.getBoolean("customMode"));
        assertEquals("Banner Test Preset", bannerJson.getString("message"));
    }

    @Test
    void updateBannerConfigurationForCustomHTMLActive() {

        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT);

        Response response = jersey.target("/v1/banner").request().header(X_API_KEY, apiKey)
                .post(Entity.entity(
                        /* language=JSON */ """
                                {"activateBanner": true, "customMode": true, "html": "<div style=\\\"position:relative;background:#321FDB;color:#fff;padding:${padding};border-bottom:1px solid rgba(0,0,0,.2);font-size:18px;line-height:1.4;text-align:center\\\"><strong>Example:</strong> <span>Your HTML-Banner Text</span>"}
                                """,
                        MediaType.APPLICATION_JSON));

        assertEquals(200, response.getStatus());
        JsonObject bannerJson = parseJsonObject(response);
        assertTrue(bannerJson.getBoolean("activateBanner"));
        assertTrue(bannerJson.getBoolean("customMode"));
        final var expected = "<div style=\"position:relative;background:#321FDB;color:#fff;padding:${padding};border-bottom:1px solid rgba(0,0,0,.2);font-size:18px;line-height:1.4;text-align:center\"><strong>Example:</strong> <span>Your HTML-Banner Text</span>";
        assertEquals(
                expected,
                bannerJson.getString("html"));
    }

    @Test
    void updateBannerConfigurationForCustomHTMLMissingHTML() {
        Response response = jersey.target("/v1/banner").request().header(X_API_KEY, apiKey)
                .post(Entity.entity(
                        /* language=JSON */ """
                                {"activateBanner": true, "customMode": true, "html": ""}
                                """,
                        MediaType.APPLICATION_JSON));

        assertEquals(400, response.getStatus());
        assertEquals("Banner HTML is required when banner is active in custom mode", getPlainTextBody(response));
    }

    @Test
    void updateBannerConfigurationForPresetMissingMessage() {
        Response response = jersey.target("/v1/banner").request().header(X_API_KEY, apiKey)
                .post(Entity.entity(
                        /* language=JSON */ """
                                {"activateBanner": true, "customMode": false, "message": ""}
                                """,
                        MediaType.APPLICATION_JSON));

        assertEquals(400, response.getStatus());
        assertEquals("Banner message is required when banner is active", getPlainTextBody(response));
    }

    @Test
    void setBannerConfigurationForPreset() {
        BannerConfig bannerConfiguration = new BannerConfig(false, true, "Test Banner", "blue", false, "");

        Response post = jersey.target("/v1/banner").request().header(X_API_KEY, apiKey).post(Entity.entity(bannerConfiguration, MediaType.APPLICATION_JSON));
        assertEquals(200, post.getStatus());
        JsonObject bannerJson = parseJsonObject(post);
        assertEquals(false, bannerJson.getBoolean("activateBanner"));
        assertEquals(true, bannerJson.getBoolean("makeBannerDismissable"));
        assertEquals("Test Banner", bannerJson.getString("message"));
        assertEquals("blue", bannerJson.getString("colorScheme"));
        assertEquals(false, bannerJson.getBoolean("customMode"));
        assertEquals("", bannerJson.getString("html"));
    }
}
