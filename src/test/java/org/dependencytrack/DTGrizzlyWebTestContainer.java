package org.dependencytrack;

import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.grizzly.servlet.WebappContext;
import org.glassfish.grizzly.ssl.SSLEngineConfigurator;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.grizzly2.httpserver.GrizzlyHttpContainer;
import org.glassfish.jersey.grizzly2.httpserver.GrizzlyHttpServerFactory;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.glassfish.jersey.test.spi.TestContainer;
import org.glassfish.jersey.test.spi.TestContainerException;
import org.glassfish.jersey.test.spi.TestHelper;

import javax.net.ssl.SSLParameters;
import javax.servlet.DispatcherType;
import javax.servlet.FilterRegistration;
import javax.servlet.ServletRegistration;
import javax.servlet.http.HttpServlet;
import javax.ws.rs.ProcessingException;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.util.EnumSet;
import java.util.EventListener;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class is largely a copy-paste of GrizzlyWebTestContainerFactory.GrizzlyWebTestContainer private class which instantiate the HTTP web server.
 *
 * In order to test REST API using DELETE method with body, the settings allowPayloadForUndefinedHttpMethods of
 * org.glassfish.grizzly.http.server.ServerConfiguration.setAllowPayloadForUndefinedHttpMethods need to be set to true.
 *
 * The only difference with the base class is the line below at #185
 * <pre>{@code
 *     server.getServerConfiguration().setAllowPayloadForUndefinedHttpMethods(true);
 * }
 * </pre>
 *
 * c.f https://stackoverflow.com/questions/49976638/allow-delete-requests-with-message-body-using-grizzly-servlet-container
 * c.f https://github.com/eclipse-ee4j/jersey/issues/3798
 *
 * @see org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory
 */
public class DTGrizzlyWebTestContainer implements TestContainer {

    private static final Logger LOGGER = Logger.getLogger(DTGrizzlyWebTestContainer.class.getName());

    private URI baseUri;

    private final ServletDeploymentContext deploymentContext;

    private HttpServer server;

    public DTGrizzlyWebTestContainer(final URI baseUri, final ServletDeploymentContext context) {
        this.baseUri = UriBuilder.fromUri(baseUri)
                .path(context.getContextPath())
                .path(context.getServletPath())
                .build();

        LOGGER.info("Creating GrizzlyWebTestContainer configured at the base URI "
                + TestHelper.zeroPortToAvailablePort(baseUri));

        this.deploymentContext = context;
        instantiateGrizzlyWebServer();
    }

    @Override
    public ClientConfig getClientConfig() {
        return null;
    }

    @Override
    public URI getBaseUri() {
        return baseUri;
    }

    @Override
    public void start() {
        if (server.isStarted()) {
            LOGGER.log(Level.WARNING, "Ignoring start request - GrizzlyWebTestContainer is already started.");

        } else {
            LOGGER.log(Level.FINE, "Starting GrizzlyWebTestContainer...");
            try {
                server.start();

                if (baseUri.getPort() == 0) {
                    baseUri = UriBuilder.fromUri(baseUri)
                            .port(server.getListener("grizzly").getPort())
                            .build();
                    LOGGER.log(Level.INFO, "Started GrizzlyWebTestContainer at the base URI " + baseUri);
                }
            } catch (final IOException ioe) {
                throw new TestContainerException(ioe);
            }
        }
    }

    @Override
    public void stop() {
        if (server.isStarted()) {
            LOGGER.log(Level.FINE, "Stopping GrizzlyWebTestContainer...");
            this.server.shutdownNow();
        } else {
            LOGGER.log(Level.WARNING, "Ignoring stop request - GrizzlyWebTestContainer is already stopped.");
        }
    }

    private void instantiateGrizzlyWebServer() {

        String contextPathLocal = deploymentContext.getContextPath();
        if (!contextPathLocal.isEmpty() && !contextPathLocal.startsWith("/")) {
            contextPathLocal = "/" + contextPathLocal;
        }

        String servletPathLocal = deploymentContext.getServletPath();
        if (!servletPathLocal.startsWith("/")) {
            servletPathLocal = "/" + servletPathLocal;
        }
        if (servletPathLocal.endsWith("/")) {
            servletPathLocal += "*";
        } else {
            servletPathLocal += "/*";
        }

        final WebappContext context = new WebappContext("TestContext", contextPathLocal);

        // servlet class and servlet instance can be both null or one of them is specified exclusively.
        final HttpServlet servletInstance = deploymentContext.getServletInstance();
        final Class<? extends HttpServlet> servletClass = deploymentContext.getServletClass();
        if (servletInstance != null || servletClass != null) {
            final ServletRegistration registration;
            if (servletInstance != null) {
                registration = context.addServlet(servletInstance.getClass().getName(), servletInstance);
            } else {
                registration = context.addServlet(servletClass.getName(), servletClass);
            }
            registration.setInitParameters(deploymentContext.getInitParams());
            registration.addMapping(servletPathLocal);
        }

        for (final Class<? extends EventListener> eventListener : deploymentContext.getListeners()) {
            context.addListener(eventListener);
        }

        final Map<String, String> contextParams = deploymentContext.getContextParams();
        for (final String contextParamName : contextParams.keySet()) {
            context.addContextInitParameter(contextParamName, contextParams.get(contextParamName));
        }

        // Filter support
        if (deploymentContext.getFilters() != null) {
            for (final ServletDeploymentContext.FilterDescriptor filterDescriptor : deploymentContext.getFilters()) {

                final FilterRegistration filterRegistration =
                        context.addFilter(filterDescriptor.getFilterName(), filterDescriptor.getFilterClass());

                filterRegistration.setInitParameters(filterDescriptor.getInitParams());
                filterRegistration.addMappingForUrlPatterns(
                        grizzlyDispatcherTypes(filterDescriptor.getDispatcherTypes()),
                        true,
                        servletPathLocal);
            }
        }

        boolean secure = false;
        SSLEngineConfigurator sslEngineConfigurator = null;
        if (deploymentContext.getSslContext().isPresent() && deploymentContext.getSslParameters().isPresent()) {
            secure = true;
            SSLParameters sslParameters = deploymentContext.getSslParameters().get();
            sslEngineConfigurator = new SSLEngineConfigurator(
                    deploymentContext.getSslContext().get(), false,
                    sslParameters.getNeedClientAuth(), sslParameters.getWantClientAuth()
            );
        }

        try {
            server = GrizzlyHttpServerFactory.createHttpServer(
                    baseUri, (GrizzlyHttpContainer) null,
                    secure, sslEngineConfigurator, false);
            server.getServerConfiguration().setAllowPayloadForUndefinedHttpMethods(true);
            context.deploy(server);
        } catch (final ProcessingException ex) {
            throw new TestContainerException(ex);
        }
    }

    private EnumSet<DispatcherType> grizzlyDispatcherTypes(final Set<DispatcherType> dispatcherTypes) {
        final Set<DispatcherType> grizzlyDispatcherTypes = new HashSet<>();
        for (final javax.servlet.DispatcherType servletDispatchType : dispatcherTypes) {
            grizzlyDispatcherTypes.add(DispatcherType.valueOf(servletDispatchType.name()));
        }
        return EnumSet.copyOf(grizzlyDispatcherTypes);
    }

}
