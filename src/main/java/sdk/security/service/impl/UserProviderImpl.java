package sdk.security.service.impl;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.web.client.RestClientException;

import sdk.security.service.IUserProvider;
import sdk.security.util.KeycloakUtil;
import sdk.security.util.RestRequestProvider;
import sdk.security.util.SecurityProvider;

/**
 * 
 * Keycloak 实现类
 */
public class UserProviderImpl implements IUserProvider {

    /**
     * 根据用户ID获取详细信息
     * @param userId[用户标识]
     * @return Map,key分别为：
     *          userId[用户ID]
     *          userName[用户名]
     *          email[邮箱]
     */
    public Map<String, String> getUserInfo(String userId) throws RestClientException{
        String realm = KeycloakUtil.getRealm();
        Map<String, Object> params = new HashMap<String, Object>();
        params.put("username", userId);
        // KeyCloak默认按照用户名模糊查找，可能结果是多个，根据入参userName过滤
        Map<String, String> result = null;
        List<Map> users = null;
        try {
            users = queryUsers(params, realm);
        } catch (Exception e) {
            throw new RestClientException("the method need user query permissions, please check.", e); 
        }
        if (users != null && users.size() > 0) {
            for (Map user : users) {
                if (user.get("username").equals(userId)) {
                    result = user;
                    break;
                }
            }
            if(result!=null){
                // 组装为通用的信息
                Map<String, String> returnMap = new HashMap<String, String>();
                returnMap.put("userId", result.get("username"));
                returnMap.put("userName", result.get("firstName"));
                returnMap.put("email", result.get("email"));
                return returnMap;
            }
        }
        
        return null;
    }
    
    /**
     * 查询用户
     * 
     * @param queryParams
     *              username 类型List<String> 模糊查找
     * @param tenantRealm
     * @param request
     * @return
     */
    public List queryUsers(Map<String, Object> queryParams, String realm) {
        Map<String, String> uriVariables = null;
        if(realm != null && !"".equals(realm)){
            uriVariables = new HashMap<String, String>();
            uriVariables.put("realm", realm);
        }
        String queryApi = KeycloakUtil.getSecurityContextUrl()+"/admin/realms/{realm}/users";
        return RestRequestProvider.get(queryApi, List.class, uriVariables, queryParams);
    }
    
    /**
     * 查询租户的用户
     */
    public List queryUsers(Map queryParams) {
    	if(queryParams.get("userName") != null) {
    		String firstName = (String) queryParams.remove("userName");
    		queryParams.put("firstName", firstName);
    	}
    	
    	if(queryParams.get("userId") != null) {
    		String userName = (String) queryParams.remove("userId");
    		queryParams.put("username", userName);
    	}
    	
    	String tenantRealm = SecurityProvider.getTenantRealm();
    	return queryUsers(queryParams, tenantRealm);
    }

}
