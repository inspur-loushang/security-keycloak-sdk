package sdk.security.service.impl;

import sdk.security.service.ISecurityProvider;
import sdk.security.util.KeycloakUtil;

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
}
