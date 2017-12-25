package sdk.security.service.impl;

import java.util.HashMap;
import java.util.Map;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;

import sdk.security.service.IAuthenticationProvider;
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

		AccessToken token = KeycloakUtil.getAccessToken();
		if (token != null) {
			return token.getPreferredUsername();
		} else {
			return null;
		}

	}

	/**
	 * 获取当前登录用户Token
	 * 
	 * @return String，token信息
	 */
	public String getToken() {
		// 本地会话存储的token
		KeycloakSecurityContext context = KeycloakUtil.getKeycloakSecurityContext();
		return context.getTokenString();
	}

	/**
	 * 获取当前登录用户userId-realmname
	 * 
	 * @return
	 */
	public String getKrbPrincipalName() {
		KeycloakSecurityContext context = KeycloakUtil.getKeycloakSecurityContext();
		AccessToken token = context.getToken();
		if (token != null) {
			return token.getPreferredUsername() + "-" + context.getRealm();
		} else {
			return null;
		}
	}
	
	/**
	 * 获取当前登录用户的详细信息
	 * 
	 * @return Map，key分别为：
	 *         userId[用户标识]，userName[用户名]，email[邮箱地址]，...
	 */
	public Map<String, String> getLoginUserInfo() {
		AccessToken token = KeycloakUtil.getAccessToken();
		if (token != null) {
			Map<String, String> map = new HashMap<String, String>();
			map.put("userId", token.getPreferredUsername());
			map.put("userName", token.getPreferredUsername());
			map.put("email", token.getEmail());
			return map;
		} else {
			return null;
		}
	}
}
