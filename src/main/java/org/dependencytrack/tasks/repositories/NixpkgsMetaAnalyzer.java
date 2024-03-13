package org.dependencytrack.tasks.repositories;

import alpine.common.logging.Logger;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.entity.BrotliInputStreamFactory;
import org.apache.hc.client5.http.entity.DecompressingEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.http.client.utils.URIBuilder;
import org.dependencytrack.exception.MetaAnalyzerException;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;

public class NixpkgsMetaAnalyzer extends AbstractMetaAnalyzer {
    private static final Logger LOGGER = Logger.getLogger(NixpkgsMetaAnalyzer.class);
    private static final String DEFAULT_CHANNEL_URL = "https://channels.nixos.org/nixpkgs-unstable/packages.json.br";
    private static NixpkgsMetaAnalyzer nixpkgsMetaAnalyzer = new NixpkgsMetaAnalyzer();
    // this doesn't really make sense wrt the "AbstractMetaAnalyzer"
    // because this statically known url will just redirect us to
    // the actual URL
    private final HashMap<String, String> latestVersion;

    private NixpkgsMetaAnalyzer() {
        this.baseUrl = DEFAULT_CHANNEL_URL;
        HashMap<String, String> newLatestVersion = new HashMap<>();

        try (final CloseableHttpResponse packagesResponse = processHttpRequest5()) {
            if (packagesResponse != null && packagesResponse.getCode() == HttpStatus.SC_OK) {
                final var entity = packagesResponse.getEntity();
                if (entity != null) {
                    // TODO(mangoiv): is this the fastest way we can do this?
                    final var entityString = EntityUtils.toString(new DecompressingEntity(entity, new BrotliInputStreamFactory()));
                    final var packages = new JSONObject(entityString).getJSONObject("packages").toMap().values();
                    packages.forEach(pkg -> {
                        // FUTUREWORK(mangoiv): there are potentially packages with the same pname
                        if (pkg instanceof JSONObject jsonPkg) {
                            final var pname = jsonPkg.getString("pname");
                            final var version = jsonPkg.getString("version");
                            newLatestVersion.putIfAbsent(pname, version);
                        }
                    });
                }

            }
        } catch (IOException ex) {
            handleRequestException(LOGGER, ex);
        } catch (Exception ex) {
            throw new MetaAnalyzerException(ex);
        }
        this.latestVersion = newLatestVersion;
        LOGGER.info("finished updating the nixpkgs meta analyzer");
    }

    public static NixpkgsMetaAnalyzer getNixpkgsMetaAnalyzer() {
        return nixpkgsMetaAnalyzer;
    }

    private CloseableHttpResponse processHttpRequest5() throws IOException {
        try {
            URIBuilder uriBuilder = new URIBuilder(baseUrl);
            final HttpGet request = new HttpGet(uriBuilder.build().toString());
            request.addHeader("accept", "application/json");
            try (final CloseableHttpClient client = HttpClients.createDefault()) {
                return client.execute(request);
            }
        } catch (URISyntaxException ex) {
            handleRequestException(LOGGER, ex);
            return null;
        }
    }

    /**
     * updates the NixpkgsMetaAnalyzer asynchronously by fetching a new version
     * of the standard channel
     */
    public void updateNixpkgsMetaAnalyzer() {
        new Thread(() -> nixpkgsMetaAnalyzer = new NixpkgsMetaAnalyzer()).start();
    }

    /**
     * {@inheritDoc}
     */
    public RepositoryType supportedRepositoryType() {
        return RepositoryType.NIXPKGS;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(Component component) {
        // FUTUREWORK(mangoiv): add nixpkgs to https://github.com/package-url/packageurl-java/blob/master/src/main/java/com/github/packageurl/PackageURL.java
        final var purl = component.getPurl();
        return purl != null && "nixpkgs".equals(purl.getType());
    }

    /**
     * {@inheritDoc}
     */
    public MetaModel analyze(Component component) {
        final var meta = new MetaModel(component);
        final var purl = component.getPurl();
        if (purl != null) {
            final var newerVersion = latestVersion.get(purl.getName());
            if (newerVersion != null) {
                meta.setLatestVersion(newerVersion);
            }
        }
        return meta;
    }
}
