package sdk.security.util;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.representations.AccessToken;

import sdk.security.userinfo.UserProvider;

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

	public static String getIDTokenString() {
		return getKeycloakSecurityContext().getIdTokenString();
	}
	
	public static String getRealm() {
		return getKeycloakSecurityContext().getRealm();
	}
	
	public static String getTenantRealm() {
		String tenantRealm = null;
		// 获取当前Realm
		String presentRealm = getRealm();
		
		/*
		 * 如果当前是Master Realm，则从Access Token的resource_access中获取对应的租户Realm；
		 * 否则，直接返回当前Realm
		 */
		if("master".equalsIgnoreCase(presentRealm)) {
			AccessToken accessToken = getAccessToken();
			
			/*
			 * 超级管理员 可以设置为某个集群的管理员
			 * 但原则上特别是Foundation上有多个集群时，集群的管理权限应该交给集群管理员，而不是超级管理员
			 */
			Set<String> roles = accessToken.getRealmAccess().getRoles();
			if(roles != null && roles.contains("admin")) {
				Map userInfo = UserProvider.getUserInfo(accessToken.getPreferredUsername());
				tenantRealm = (String) userInfo.get("tenantRealm");
				return tenantRealm;
			}
			
			Map<String, AccessToken.Access> resourcAccesses = accessToken.getResourceAccess();
			Set<String> clients = resourcAccesses.keySet();
			for (String client : clients) {
				if (client.endsWith("-realm") && !"master-realm".equalsIgnoreCase(client)
						&& !"templatetenant-realm".equalsIgnoreCase(client)) {
					presentRealm = client.substring(0, client.indexOf("-realm"));
					// 一个管理员仅对应一个Realm
					break;
				}
			}
			
		}
		
		return presentRealm;		
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
