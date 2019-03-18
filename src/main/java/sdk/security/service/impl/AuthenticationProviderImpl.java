package sdk.security.service.impl;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;

import sdk.security.service.IAuthenticationProvider;
import sdk.security.util.HttpServletThreadLocal;
import sdk.security.util.KeycloakUtil;

/**
 * 认证
 *
 */
public class AuthenticationProviderImpl implements IAuthenticationProvider {

	/**
	 * 获取当前登录用户标识
	 * 
	 * @return String userId[用户ID]
	 */
	public String getLoginUserId() {
		try {
			AccessToken token = KeycloakUtil.getAccessToken();
			return token.getPreferredUsername();
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * 获取当前登录用户Token
	 * 
	 * @return String，token信息
	 */
	public String getToken() {
		try {
			return KeycloakUtil.getAccessTokenString();
		} catch (Exception e) {
			return null;
		}
	}
	
	public String getIDToken() {
		try {
			return KeycloakUtil.getIDTokenString();
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * 获取当前登录用户userId-realmname
	 * 
	 * @return
	 */
	public String getKrbPrincipalName() {
		try {
			KeycloakSecurityContext context = KeycloakUtil.getKeycloakSecurityContext();
			AccessToken token = context.getToken();
			return token.getPreferredUsername() + "-" + context.getRealm();
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * 获取当前登录用户的详细信息
	 * 
	 * @return Map，key分别为： userId[用户标识]，userName[用户名]，email[邮箱地址]，...
	 */
	public Map<String, String> getLoginUserInfo() {
		try {
			AccessToken token = KeycloakUtil.getAccessToken();
			Map<String, String> map = new HashMap<String, String>();
			map.put("userId", token.getPreferredUsername());
			map.put("userName", token.getPreferredUsername());
			map.put("email", token.getEmail());
			return map;
		} catch (Exception e) {
			return null;
		}
	}
	
	public void setCustomSessionInfo(String key, Object value) {
		HttpServletRequest request = HttpServletThreadLocal.getRequest();
		if (request == null) {
			return;
		}
		HttpSession session = request.getSession(true);
		session.setAttribute(key, value);
	}
	
	public Object getCustomSessionInfo(String key) {
		HttpServletRequest request = HttpServletThreadLocal.getRequest();
		if (request == null) {
			return null;
		}
		HttpSession session = request.getSession(true);
		return session.getAttribute(key);
	}
}
