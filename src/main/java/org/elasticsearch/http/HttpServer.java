/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.http;

import static org.elasticsearch.rest.RestStatus.FORBIDDEN;
import static org.elasticsearch.rest.RestStatus.INTERNAL_SERVER_ERROR;
import static org.elasticsearch.rest.RestStatus.NOT_FOUND;
import static org.elasticsearch.rest.RestStatus.OK;
import static org.elasticsearch.rest.RestStatus.UNAUTHORIZED;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.elasticsearch.common.Base64;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.breaker.CircuitBreaker;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.FileSystemUtils;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.env.Environment;
import org.elasticsearch.http.auth.Client;
import org.elasticsearch.http.auth.InetAddressWhitelist;
import org.elasticsearch.http.auth.ProxyChains;
import org.elasticsearch.http.auth.XForwardedFor;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.node.service.NodeService;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestFilter;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;

import com.google.common.collect.ImmutableMap;
import com.google.common.io.ByteStreams;

/**
 * YuShengqiang 基于elasticsearch-2.4.6-sources.jar 增加白名单及http basic认证 
 */
public class HttpServer extends AbstractLifecycleComponent<HttpServer> {

    private final Environment environment;

    private final HttpServerTransport transport;

    private final RestController restController;

    private final NodeService nodeService;

    private final boolean disableSites;

    private final PluginSiteFilter pluginSiteFilter = new PluginSiteFilter();

    private final CircuitBreakerService circuitBreakerService;
    
    
    private final boolean enabled;
	private final String user;
	private final String password;
	private final InetAddressWhitelist whitelist;
	private final ProxyChains proxyChains;
	private final String xForwardHeader;
	private final boolean log;

    @Inject
    public HttpServer(Settings settings, Environment environment, HttpServerTransport transport, RestController restController, NodeService nodeService,
                      CircuitBreakerService circuitBreakerService) {
        super(settings);
        this.environment = environment;
        this.transport = transport;
        this.restController = restController;
        this.nodeService = nodeService;
        this.circuitBreakerService = circuitBreakerService;
        nodeService.setHttpServer(this);

        this.disableSites = this.settings.getAsBoolean("http.disable_sites", false);

        transport.httpServerAdapter(new Dispatcher(this));
        
        this.user = settings.get("http.basic.user", "admin");
		this.password = settings.get("http.basic.password", "admin_pw");
		final boolean whitelistEnabled = settings.getAsBoolean("http.basic.ipwhitelist", true);
		String[] whitelisted = new String[0];
		if (whitelistEnabled) {
			whitelisted = settings.getAsArray("http.basic.ipwhitelist", new String[] { "localhost", "127.0.0.1" });
		}
		this.whitelist = new InetAddressWhitelist(whitelisted);
		this.proxyChains = new ProxyChains(settings.getAsArray("http.basic.trusted_proxy_chains", new String[] { "" }));

		// for AWS load balancers it is X-Forwarded-For -> hmmh does not work
		this.xForwardHeader = settings.get("http.basic.xforward", "");
		this.log = settings.getAsBoolean("http.basic.log", true);
		this.enabled = settings.getAsBoolean("http.basic.enabled", false);
		if(this.enabled) {
			Loggers.getLogger(getClass()).info(
					"using {}:{} with whitelist: {}, xforward header field: {}, trusted proxy chain: {}", user, password,
					whitelist, xForwardHeader, proxyChains);
		}
    }

    static class Dispatcher implements HttpServerAdapter {

        private final HttpServer server;

        Dispatcher(HttpServer server) {
            this.server = server;
        }

        @Override
        public void dispatchRequest(RestRequest request, RestChannel channel) {
            server.internalDispatchRequest(request, channel);
        }
    }

    @Override
    protected void doStart() {
        transport.start();
        if (logger.isInfoEnabled()) {
            logger.info("{}", transport.boundAddress());
        }
        nodeService.putAttribute("http_address", transport.boundAddress().publishAddress().toString());
    }

    @Override
    protected void doStop() {
        nodeService.removeAttribute("http_address");
        transport.stop();
    }

    @Override
    protected void doClose() {
        transport.close();
    }

    public HttpInfo info() {
        return transport.info();
    }

    public HttpStats stats() {
        return transport.stats();
    }
    
    private void dispatchRequest(final RestRequest request, final RestChannel channel) {
        String rawPath = request.rawPath();
        if (rawPath.startsWith("/_plugin/")) {
            RestFilterChain filterChain = restController.filterChain(pluginSiteFilter);
            filterChain.continueProcessing(request, channel);
            return;
        } else if (rawPath.equals("/favicon.ico")) {
            handleFavicon(request, channel);
            return;
        }
        RestChannel responseChannel = channel;
        try {
            int contentLength = request.content().length();
            if (restController.canTripCircuitBreaker(request)) {
                inFlightRequestsBreaker(circuitBreakerService).addEstimateBytesAndMaybeBreak(contentLength, "<http_request>");
            } else {
                inFlightRequestsBreaker(circuitBreakerService).addWithoutBreaking(contentLength);
            }
            // iff we could reserve bytes for the request we need to send the response also over this channel
            responseChannel = new ResourceHandlingHttpChannel(channel, circuitBreakerService);
            restController.dispatchRequest(request, responseChannel);
        } catch (Throwable t) {
            restController.sendErrorResponse(request, responseChannel, t);
        }
    }

    public void internalDispatchRequest(final RestRequest request, final RestChannel channel) {
    	if(!this.enabled) {
    		dispatchRequest(request, channel);
    	} else {
        	if (log) {
                logRequest(request);
            }

            if (authorized(request)) {
            	dispatchRequest(request, channel);
            } else if (healthCheck(request)) { // display custom health check page when unauthorized (do not display too much server info)
                channel.sendResponse(new BytesRestResponse(OK, "{\"OK\":{}}"));
            } else {
                logUnAuthorizedRequest(request);
                BytesRestResponse response = new BytesRestResponse(UNAUTHORIZED, "Authentication Required");
                response.addHeader("WWW-Authenticate", "Basic realm=\"Restricted\"");
                channel.sendResponse(response);
            }
    	}
    }
    
    public void logRequest(final RestRequest request) {
        String addr = getAddress(request).getHostAddress();
        String t = "Authorization:{}, type: {}, Host:{}, Path:{}, {}:{}, Request-IP:{}, " +
          "Client-IP:{}, X-Client-IP{}";
        logger.info(t,
                    request.header("Authorization"),
                    request.method(),
                    request.header("Host"),
                    request.path(),
                    xForwardHeader,
                    request.header(xForwardHeader),
                    addr,
                    request.header("X-Client-IP"),
                    request.header("Client-IP"));
      }

      public void logUnAuthorizedRequest(final RestRequest request) {
          String addr = getAddress(request).getHostAddress();
          String t = "UNAUTHORIZED type:{}, address:{}, path:{}, request:{},"
            + "content:{}, credentials:{}";
          Loggers.getLogger(getClass()).error(t,
                  request.method(), addr, request.path(), request.params(),
                  request.content().toUtf8(), getDecoded(request));
      }

	// @param an http method
	// @returns True iff the method is one of the methods used for health check
	private boolean isHealthCheckMethod(final RestRequest.Method method) {
		final RestRequest.Method[] healthCheckMethods = { RestRequest.Method.GET, RestRequest.Method.HEAD };
		return Arrays.asList(healthCheckMethods).contains(method);
	}

	// @param an http Request
	// @returns True iff we check the root path and is a method allowed for
	// healthCheck
	private boolean healthCheck(final RestRequest request) {
		return request.path().equals("/") && isHealthCheckMethod(request.method());
	}

	/**
	 *
	 *
	 * @param request
	 * @return true if the request is authorized
	 */
	private boolean authorized(final RestRequest request) {
		return allowOptionsForCORS(request) || authBasic(request) || ipAuthorized(request);
	}

	/**
	 *
	 *
	 * @param request
	 * @return true iff the client is authorized by ip
	 */
	private boolean ipAuthorized(final RestRequest request) {
		boolean ipAuthorized = false;
		String xForwardedFor = request.header(xForwardHeader);
		Client client = new Client(getAddress(request), whitelist, new XForwardedFor(xForwardedFor), proxyChains);
		ipAuthorized = client.isAuthorized();
		if (ipAuthorized) {
			if (log) {
				String template = "Ip Authorized client: {}";
				Loggers.getLogger(getClass()).info(template, client);
			}
		} else {
			String template = "Ip Unauthorized client: {}";
			Loggers.getLogger(getClass()).error(template, client);
		}
		return ipAuthorized;
	}

	public String getDecoded(RestRequest request) {
		String authHeader = request.header("Authorization");
		if (authHeader == null)
			return "";

		String[] split = authHeader.split(" ", 2);
		if (split.length != 2 || !split[0].equals("Basic"))
			return "";
		try {
			return new String(Base64.decode(split[1]));
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
	}

	private boolean authBasic(final RestRequest request) {
		String decoded = "";
		try {
			decoded = getDecoded(request);
			if (!decoded.isEmpty()) {
				String[] userAndPassword = decoded.split(":", 2);
				String givenUser = userAndPassword[0];
				String givenPass = userAndPassword[1];
				if (this.user.equals(givenUser) && this.password.equals(givenPass))
					return true;
			}
		} catch (Exception e) {
			logger.warn("Retrieving of user and password failed for " + decoded + " ," + e.getMessage());
		}
		return false;
	}

	/**
	 *
	 *
	 * @param request
	 * @return the IP adress of the direct client
	 */
	private InetAddress getAddress(RestRequest request) {
		return ((InetSocketAddress) request.getRemoteAddress()).getAddress();
	}

	/**
	 * https://en.wikipedia.org/wiki/Cross-origin_resource_sharing the specification
	 * mandates that browsers “preflight” the request, soliciting supported methods
	 * from the server with an HTTP OPTIONS request
	 */
	private boolean allowOptionsForCORS(RestRequest request) {
		// in elasticsearch.yml set
		// http.cors.allow-headers: "X-Requested-With, Content-Type, Content-Length,
		// Authorization"
		if (request.method() == Method.OPTIONS) {
			// Loggers.getLogger(getClass()).error("CORS type {}, address {}, path {},
			// request {}, content {}",
			// request.method(), getAddress(request), request.path(), request.params(),
			// request.content().toUtf8());
			return true;
		}
		return false;
	}


    class PluginSiteFilter extends RestFilter {

        @Override
        public void process(RestRequest request, RestChannel channel, RestFilterChain filterChain) throws IOException {
            handlePluginSite(request, channel);
        }
    }

    void handleFavicon(RestRequest request, RestChannel channel) {
        if (request.method() == RestRequest.Method.GET) {
            try {
                try (InputStream stream = getClass().getResourceAsStream("/config/favicon.ico")) {
                    byte[] content = ByteStreams.toByteArray(stream);
                    BytesRestResponse restResponse = new BytesRestResponse(RestStatus.OK, "image/x-icon", content);
                    channel.sendResponse(restResponse);
                }
            } catch (IOException e) {
                channel.sendResponse(new BytesRestResponse(INTERNAL_SERVER_ERROR));
            }
        } else {
            channel.sendResponse(new BytesRestResponse(FORBIDDEN));
        }
    }

    void handlePluginSite(RestRequest request, RestChannel channel) throws IOException {
        if (disableSites) {
            channel.sendResponse(new BytesRestResponse(FORBIDDEN));
            return;
        }
        if (request.method() == RestRequest.Method.OPTIONS) {
            // when we have OPTIONS request, simply send OK by default (with the Access Control Origin header which gets automatically added)
            channel.sendResponse(new BytesRestResponse(OK));
            return;
        }
        if (request.method() != RestRequest.Method.GET) {
            channel.sendResponse(new BytesRestResponse(FORBIDDEN));
            return;
        }
        // TODO for a "/_plugin" endpoint, we should have a page that lists all the plugins?

        String path = request.rawPath().substring("/_plugin/".length());
        int i1 = path.indexOf('/');
        String pluginName;
        String sitePath;
        if (i1 == -1) {
            pluginName = path;
            sitePath = null;
            // If a trailing / is missing, we redirect to the right page #2654
            String redirectUrl = request.rawPath() + "/";
            BytesRestResponse restResponse = new BytesRestResponse(RestStatus.MOVED_PERMANENTLY, "text/html", "<head><meta http-equiv=\"refresh\" content=\"0; URL=" + redirectUrl + "\"></head>");
            restResponse.addHeader("Location", redirectUrl);
            channel.sendResponse(restResponse);
            return;
        } else {
            pluginName = path.substring(0, i1);
            sitePath = path.substring(i1 + 1);
        }

        // we default to index.html, or what the plugin provides (as a unix-style path)
        // this is a relative path under _site configured by the plugin.
        if (sitePath.length() == 0) {
            sitePath = "index.html";
        } else {
            // remove extraneous leading slashes, its not an absolute path.
            while (sitePath.length() > 0 && sitePath.charAt(0) == '/') {
                sitePath = sitePath.substring(1);
            }
        }
        final Path siteFile = environment.pluginsFile().resolve(pluginName).resolve("_site");

        final String separator = siteFile.getFileSystem().getSeparator();
        // Convert file separators.
        sitePath = sitePath.replace("/", separator);

        Path file = siteFile.resolve(sitePath);

        // return not found instead of forbidden to prevent malicious requests to find out if files exist or dont exist
        if (!Files.exists(file) || FileSystemUtils.isHidden(file) || !file.toAbsolutePath().normalize().startsWith(siteFile.toAbsolutePath().normalize())) {
            channel.sendResponse(new BytesRestResponse(NOT_FOUND));
            return;
        }

        BasicFileAttributes attributes = Files.readAttributes(file, BasicFileAttributes.class);
        if (!attributes.isRegularFile()) {
            // If it's not a dir, we send a 403
            if (!attributes.isDirectory()) {
                channel.sendResponse(new BytesRestResponse(FORBIDDEN));
                return;
            }
            // We don't serve dir but if index.html exists in dir we should serve it
            file = file.resolve("index.html");
            if (!Files.exists(file) || FileSystemUtils.isHidden(file) || !Files.isRegularFile(file)) {
                channel.sendResponse(new BytesRestResponse(FORBIDDEN));
                return;
            }
        }

        try {
            byte[] data = Files.readAllBytes(file);
            channel.sendResponse(new BytesRestResponse(OK, guessMimeType(sitePath), data));
        } catch (IOException e) {
            channel.sendResponse(new BytesRestResponse(INTERNAL_SERVER_ERROR));
        }
    }


    // TODO: Don't respond with a mime type that violates the request's Accept header
    private String guessMimeType(String path) {
        int lastDot = path.lastIndexOf('.');
        if (lastDot == -1) {
            return "";
        }
        String extension = path.substring(lastDot + 1).toLowerCase(Locale.ROOT);
        String mimeType = DEFAULT_MIME_TYPES.get(extension);
        if (mimeType == null) {
            return "";
        }
        return mimeType;
    }

    static {
        // This is not an exhaustive list, just the most common types. Call registerMimeType() to add more.
        Map<String, String> mimeTypes = new HashMap<>();
        mimeTypes.put("txt", "text/plain");
        mimeTypes.put("css", "text/css");
        mimeTypes.put("csv", "text/csv");
        mimeTypes.put("htm", "text/html");
        mimeTypes.put("html", "text/html");
        mimeTypes.put("xml", "text/xml");
        mimeTypes.put("js", "text/javascript"); // Technically it should be application/javascript (RFC 4329), but IE8 struggles with that
        mimeTypes.put("xhtml", "application/xhtml+xml");
        mimeTypes.put("json", "application/json");
        mimeTypes.put("pdf", "application/pdf");
        mimeTypes.put("zip", "application/zip");
        mimeTypes.put("tar", "application/x-tar");
        mimeTypes.put("gif", "image/gif");
        mimeTypes.put("jpeg", "image/jpeg");
        mimeTypes.put("jpg", "image/jpeg");
        mimeTypes.put("tiff", "image/tiff");
        mimeTypes.put("tif", "image/tiff");
        mimeTypes.put("png", "image/png");
        mimeTypes.put("svg", "image/svg+xml");
        mimeTypes.put("ico", "image/vnd.microsoft.icon");
        mimeTypes.put("mp3", "audio/mpeg");
        DEFAULT_MIME_TYPES = ImmutableMap.copyOf(mimeTypes);
    }

    public static final Map<String, String> DEFAULT_MIME_TYPES;

    private static final class ResourceHandlingHttpChannel implements RestChannel {
        private final RestChannel delegate;
        private final CircuitBreakerService circuitBreakerService;
        private final AtomicBoolean closed = new AtomicBoolean();

        public ResourceHandlingHttpChannel(RestChannel delegate, CircuitBreakerService circuitBreakerService) {
            this.delegate = delegate;
            this.circuitBreakerService = circuitBreakerService;
        }

        @Override
        public XContentBuilder newBuilder() throws IOException {
            return delegate.newBuilder();
        }

        @Override
        public XContentBuilder newErrorBuilder() throws IOException {
            return delegate.newErrorBuilder();
        }

        @Override
        public XContentBuilder newBuilder(@Nullable BytesReference autoDetectSource, boolean useFiltering) throws IOException {
            return delegate.newBuilder(autoDetectSource, useFiltering);
        }

        @Override
        public BytesStreamOutput bytesOutput() {
            return delegate.bytesOutput();
        }

        @Override
        public RestRequest request() {
            return delegate.request();
        }

        @Override
        public boolean detailedErrorsEnabled() {
            return delegate.detailedErrorsEnabled();
        }

        @Override
        public void sendResponse(RestResponse response) {
            close();
            delegate.sendResponse(response);
        }

        private void close() {
            // attempt to close once atomically
            if (closed.compareAndSet(false, true) == false) {
                throw new IllegalStateException("Channel is already closed");
            }
            inFlightRequestsBreaker(circuitBreakerService).addWithoutBreaking(-request().content().length());
        }

    }

    private static CircuitBreaker inFlightRequestsBreaker(CircuitBreakerService circuitBreakerService) {
        // We always obtain a fresh breaker to reflect changes to the breaker configuration.
        return circuitBreakerService.getBreaker(CircuitBreaker.IN_FLIGHT_REQUESTS);
    }
}
