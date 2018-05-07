package sdk.security.util;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import sdk.security.util.PathBasedKeycloakConfigResolver;

/**
 * REST API安全调用
 * 
 * @author Data Security Group
 *
 */
public class RestRequestUtils {

	private static RestTemplate restTemplate = new RestTemplate();

	private static String authServerUrl;
	private static String realm;
	private static String resource;

	static {
		// KeycloakDeployment deployment = new
		// PathBasedKeycloakConfigResolver().resolve(null);
		KeycloakDeployment deployment = PathBasedKeycloakConfigResolver.nowDeployment;
		authServerUrl = deployment.getAuthServerBaseUrl();
		realm = deployment.getRealm();
		resource = deployment.getResourceName();

	}

	private static String integrate(String url, Map uriVariables, HttpServletRequest request) {
		if (!uriVariables.containsKey("realm")) {
			uriVariables.put("realm", realm);
		}

		if (url.startsWith("http") || url.startsWith("https")) {
			return url;
		}
		StringBuilder sr = new StringBuilder(authServerUrl);
		sr.append(url);
		return sr.toString();
	}

	/**
	 * 构建HTTP Header Authorization
	 * 
	 * @param httpServletRequest
	 * @return HttpHeaders
	 */
	private static HttpHeaders buildAuthorizationHeader(HttpServletRequest httpServletRequest) {

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		headers.setContentType(MediaType.APPLICATION_JSON);
		//headers.add("Authorization", "bearer " + context.getTokenString());

		return headers;
	}

	public static <T> T get(String url, Class<T> responseType, Map uriVariables, MultiValueMap queryVariables,
			HttpServletRequest request) {

		if (uriVariables == null) {
			uriVariables = new HashMap();
		}

		String endpoint = integrate(url, uriVariables, request);

		HttpEntity<Map> entity = new HttpEntity<Map>(buildAuthorizationHeader(request));

		if (queryVariables != null && !queryVariables.isEmpty()) {
			UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(endpoint);
			builder.queryParams(queryVariables);
			endpoint = builder.build().toUriString();
		}

		HttpEntity<T> response = restTemplate.exchange(endpoint, HttpMethod.GET, entity, responseType, uriVariables);
		return response.getBody();
	}


}
