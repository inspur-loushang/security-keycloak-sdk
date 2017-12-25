package sdk.security.util;

import java.net.MalformedURLException;
import java.net.URL;

import javax.servlet.http.HttpServletRequest;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.representations.AccessToken;

public class KeycloakUtil {

	private static final String logout = "/protocol/openid-connect/logout?redirect_uri=";

	public static KeycloakSecurityContext getKeycloakSecurityContext() {
		HttpServletRequest request = HttpServletThreadLocal.getRequest();
		RefreshableKeycloakSecurityContext context = (RefreshableKeycloakSecurityContext) request
				.getAttribute(KeycloakSecurityContext.class.getName());
		return context;
	}

	public static AccessToken getAccessToken() {
		return getKeycloakSecurityContext().getToken();
	}

	public static String getAccessTokenString() {
		return getKeycloakSecurityContext().getTokenString();
	}

	public static String getRealm() {
		return getKeycloakSecurityContext().getRealm();

	}

	public static String getSecurityContextUrl() {
		String authServerUrl = "";
		AccessToken token = getAccessToken();
		String issuer = token.getIssuer();
		try {
			URL url = new URL(issuer);
			authServerUrl = url.getProtocol() + "://" + url.getHost() + ":" + url.getPort() + "/auth";

		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		return authServerUrl;
	}

	/**
	 * 回退URL
	 * @param backUrl
	 * @return
	 */
	public static String getLogoutUrl(String backUrl) {
		String logoutUrl = "";
		if (!"".equals(backUrl) && backUrl != null) {
			logoutUrl = getAccessToken().getIssuer() + logout;
			if (backUrl.startsWith("http") || backUrl.startsWith("https")) {
				logoutUrl += backUrl;
			} else {
				try {
					HttpServletRequest request = HttpServletThreadLocal.getRequest();
					String contexPath = request.getContextPath();
					URL url = new URL(request.getRequestURL().toString());
					String protocol = url.getProtocol();
					String host = url.getHost();
					int port = url.getPort();
					logoutUrl += protocol + "://" + host;
					if (port > 0) {
						logoutUrl += ":" + port;
					}
					if (backUrl.startsWith("/")) {
						logoutUrl += contexPath + backUrl;
					} else {
						logoutUrl += contexPath + "/" + backUrl;
					}
				} catch (MalformedURLException e) {
					e.printStackTrace();
				}
			}

		}
		return logoutUrl;
	}
}
