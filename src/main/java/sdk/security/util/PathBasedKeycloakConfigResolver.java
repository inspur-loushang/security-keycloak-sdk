package sdk.security.util;

import com.google.gson.Gson;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringBufferInputStream;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.spi.HttpFacade.Cookie;
import org.keycloak.adapters.spi.HttpFacade.Request;

/**
 * Resolve configuration of Keycloak
 * 
 * @author Data Security Group
 *
 */
public class PathBasedKeycloakConfigResolver implements KeycloakConfigResolver {
	private Log logger = LogFactory.getLog(PathBasedKeycloakConfigResolver.class);

	private final Map<String, KeycloakDeployment> cache = new ConcurrentHashMap();

	public static KeycloakDeployment nowDeployment = null;

	public KeycloakDeployment resolve(Request request) {
		String realm = null;
		String path = request.getURI();

		// get realm from request url
		int multitenantIndex = path.indexOf("?realm=");
		if (multitenantIndex > -1) {
			realm = path.substring(multitenantIndex).split("=")[1];
			if (realm.contains("&")) {
				realm = realm.split("&")[0];
			}
		}
		
		// get realm from request Referer Header
		if(realm == null) {
			String referer = request.getHeader("Referer");
			if(referer!=null && referer.contains("?realm=")) {
				int refererMultitenantIndex = referer.indexOf("?realm=");
				realm = referer.substring(refererMultitenantIndex).split("=")[1];
				if (realm.contains("&")) {
					realm = realm.split("&")[0];
				}
			}
		}
		
		// get realm from static variable named cache
		if(realm == null && cache.get("master") != null) {
			realm = "master";
		}

		// get realm from cookie named mt
		if (realm == null) {
			Cookie mtCookie = request.getCookie("mt");
			if (mtCookie != null) {
				realm = mtCookie.getValue();
			}
		}

		// TODO 验证从cache中判断后，是否还需要从logout url中获取；验证多租户tenant的退出是否有效且不影响其他tenant
		if (realm == null) {
			realm = getRealmNameForLogout(path);
		}
		if (realm == null) {
			return new KeycloakDeployment();
		}

		KeycloakDeployment deployment = this.cache.get(realm);

		nowDeployment = deployment;
		if (deployment == null) {
			InputStream is = getClass().getResourceAsStream("/keycloak.json");
			if (is == null) {
				throw new IllegalStateException("Not able to find the file keycloak.json");
			}

			try {
				Reader reader = new InputStreamReader(is, "UTF-8");
				Map map = (Map) new Gson().fromJson(reader, Map.class);
				map.put("realm", realm);

				String config = new Gson().toJson(map);
				is = new StringBufferInputStream(config);
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}

			deployment = KeycloakDeploymentBuilder.build(is);
			this.cache.put(realm, deployment);
			nowDeployment = deployment;
		}

		return deployment;
	}

	private String getRealmNameForLogout(String url) {
		String realm = null;
		int index1 = url.lastIndexOf("k_logout");
		if (index1 > 0) {
			try {
				String urla = url.substring(0, index1 - 1);
				int index2 = urla.lastIndexOf("/");
				realm = urla.substring(index2 + 1, urla.length());
			} catch (Exception e) {
				this.logger.error("get realm fails for client logout, error info ", e);
				e.printStackTrace();
			}
		}
		return realm;
	}
	
}