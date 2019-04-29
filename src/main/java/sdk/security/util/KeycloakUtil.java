package sdk.security.util;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.springframework.http.HttpEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.google.gson.Gson;

import sdk.security.userinfo.UserProvider;

public class KeycloakUtil {

	private static final String logout = "/protocol/openid-connect/logout?redirect_uri=";
	private static final String AUTH_TOKEN = "/realms/{realm}/protocol/openid-connect/token";
	
	public static KeycloakSecurityContext getKeycloakSecurityContext() {
		HttpServletRequest request = HttpServletThreadLocal.getRequest();
		if(request == null) {
			return null;
		}
		RefreshableKeycloakSecurityContext context = (RefreshableKeycloakSecurityContext) request
				.getAttribute(KeycloakSecurityContext.class.getName());
		return context;
	}

	public static AccessToken getAccessToken() {
		KeycloakSecurityContext sc = getKeycloakSecurityContext();
		if(sc == null) {
			return null;
		}
		return sc.getToken();
	}

	public static String getAccessTokenString() {
		KeycloakSecurityContext sc = getKeycloakSecurityContext();
		if(sc == null) {
			return null;
		}
		return sc.getTokenString();
	}

	public static String getIDTokenString() {
		KeycloakSecurityContext sc = getKeycloakSecurityContext();
		if(sc == null) {
			return null;
		}
		return sc.getIdTokenString();
	}
	
	public static String getRealm() {
		KeycloakSecurityContext sc = getKeycloakSecurityContext();
		if(sc == null) {
			return null;
		}
		return sc.getRealm();
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
		if(token == null) {
			return null;
		}
		
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
		AccessToken accessToken = getAccessToken();
		if(accessToken == null) {
			return null;
		}
		
		if (!"".equals(backUrl) && backUrl != null) {
			logoutUrl = accessToken.getIssuer() + logout;
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
	
	
	public static Map auth(String userId, String password, String clientId, String realm) {
		Map<String, String> uriVariables = new HashMap<String, String>();
		MultiValueMap<String, String> bodyVariables = new LinkedMultiValueMap<String, String>();
		bodyVariables.add("username", userId);
		bodyVariables.add("password", password);
		bodyVariables.add("grant_type", "password");
		bodyVariables.add("scope", "openid profile");
		bodyVariables.add("client_id", clientId);
		
		uriVariables.put("realm", realm);
		
		Map keycloakInfo = readKeycloakJsonFile();
		String keycloakAuthUrl = (String) keycloakInfo.get("auth-server-url");
		StringBuffer sr = new StringBuffer();
		if(keycloakAuthUrl!=null) {
			sr.append(keycloakAuthUrl);
		}
		sr.append(AUTH_TOKEN);

		HttpEntity<Map> response = RestRequestUtils.post(sr.toString(), Map.class, uriVariables, bodyVariables);
		return response.getBody();
	}
	
	/**
	 * 使用codeadmin用户重新生成access_token，
	 * 将新增的realm的权限加入到access_token中，只有这样才有权限创建realm管理员
	 * 
	 * @return
	 */
	public static String impersonate() {
		try {
			Map map = auth("codeadmin",
					"6ImNvZGUiLCJjb2RlX2NoYWxsZW5nZV9tZXRob2Q", "indata-manage-portal", "master");
			return (String) map.get("access_token");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	private static Map readKeycloakJsonFile() {
		Map map = new HashMap();
		InputStream is = KeycloakUtil.class.getClassLoader().getResourceAsStream("/keycloak.json");
		if (is == null) {
			throw new IllegalStateException("Not able to find the file keycloak.json");
		}

		try {
			Reader reader = new InputStreamReader(is, "UTF-8");
			map = (Map) new Gson().fromJson(reader, Map.class);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return map;
	}
	
	public static String getAuthServerUrl() {
		Map keycloakInfo = readKeycloakJsonFile();
		String keycloakAuthUrl = (String) keycloakInfo.get("auth-server-url");
		return keycloakAuthUrl;
	}
}
