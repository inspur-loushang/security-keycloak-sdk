package sdk.security.service.impl;

import java.util.HashMap;
import java.util.Map;

import sdk.security.service.ISecurityProvider;
import sdk.security.util.KeycloakUtil;
import sdk.security.util.PropertiesUtil;
import sdk.security.util.RestRequestUtils;
import sdk.security.util.StringUtil;

/**
 * Keycloak 实现类
 * 
 */
public class SecurityProviderImpl implements ISecurityProvider {

    /**
     * 获取安全中心的服务根地址
     * 
     * @return String 服务根URL
     */
    public String getSecurityContextUrl(){
        return KeycloakUtil.getSecurityContextUrl();
    }

    /**
     * 获取注销url
     * 
     * @param backUrl
     * @return
     */
    public String getLogoutUrl(String backUrl){
        return KeycloakUtil.getLogoutUrl(backUrl);
    }
    
    public String getRealmInfo(){
    	return KeycloakUtil.getRealm();
    }
    
    public String getTenantRealm() {
    	return KeycloakUtil.getTenantRealm();
	}

	public Map<String, String> getTenantAdminUser() {
		String presentRealm = getTenantRealm();
		
		return getTenantAdminUser(presentRealm);
	}
	
	public Map<String, String> getTenantAdminUser(String tenantRealm) {
		String adminUserEndpoint = "/indata-manage-portal/service/api/manage/tenants/realm/{realm}/adminuser";
		Map<String, String> user = new HashMap<String, String>();
		
		StringBuffer sr = new StringBuffer();
		sr.append(getManagePortalServer());
		sr.append(adminUserEndpoint);
		
		Map<String, String> uriVariables = null;
		if(tenantRealm != null && !"".equals(tenantRealm)){
			uriVariables = new HashMap<String, String>();
			uriVariables.put("realm", tenantRealm);
		}
		
		user = RestRequestUtils.get(sr.toString(), Map.class, uriVariables, null, null);
		return user;

	}
	
	/**
	 * 获取管理员门户地址
	 * 
	 * @return String http://127.0.0.1:9000
	 */
	private String getManagePortalServer() {
		StringBuffer sr = new StringBuffer();
		
		// HTTP
		String scheme = "http";
		sr.append(scheme);
		sr.append("://");
		
		// 管理员门户地址: bigdata.manage.domain=127.0.0.1:9000
		String domainConf  = PropertiesUtil.getValue("conf.properties", "bigdata.manage.domain");
		
		if(!StringUtil.isEmptyString(domainConf)) {
			sr.append(domainConf);
		} else {
			// 使用约定的9000端口
			String server = PropertiesUtil.getValue("conf.properties", "bigdata.domain");
			if (server != null && server.contains(":")) {
				server = server.split(":")[0];
			}
			
			sr.append(server);
			sr.append(":9000");
		}
		
		return sr.toString();		
	}
}
