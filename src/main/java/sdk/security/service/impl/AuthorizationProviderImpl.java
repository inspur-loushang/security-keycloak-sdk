package sdk.security.service.impl;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.keycloak.representations.AccessToken;

import sdk.security.service.IAuthorizationProvider;
import sdk.security.util.KeycloakUtil;
import sdk.security.util.ResourceUtil;

/**
 * 授权
 *
 */
public class AuthorizationProviderImpl implements IAuthorizationProvider {

	/**
	 * 判断当前登录用户对指定资源是否有权限
	 * 
	 * @param resourceId
	 *            [资源标识]
	 *
	 * @return true[有权限]，false[无权限]
	 */
	public boolean hasPermission(String resourceId) {

		if (!"".equals(resourceId) && resourceId != null) {
			// 获取当前登录用户有权限的资源；
			List<Map<String, String>> resources = getResources(null);
			// 遍历资源判定权限；
			Iterator<Map<String, String>> iterator = resources.iterator();
			while (iterator.hasNext()) {
				if (iterator.next().get("rid").equals(resourceId)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * 获取当前登录用户有权限的资源信息
	 * 
	 * @param type
	 *            [资源类型，可为空]
	 *
	 * @return List，内容为Map，key分别为：rid[资源ID]，url[资源url]，type[资源类型]，. ..
	 */
	public List<Map<String, String>> getResources(String type) {
		AccessToken token = KeycloakUtil.getAccessToken();
		List<Map<String, String>> list = new ArrayList<Map<String, String>>();
		if (token != null) {
			// 当前登录用户有权限的资源集合
			//读取securitySDKAuthz.json文件
			List<Map<String, Object>> authzResource = ResourceUtil.getAuthzResource();
			if(!authzResource.isEmpty()){
				// 当前登录用户角色迭代器
				Iterator<String> rolesIterator = token.getRealmAccess().getRoles().iterator();
				// 遍历用户角色
				while (rolesIterator.hasNext()) {
					String curUseRoleId = rolesIterator.next();
					// 授权资源元数据迭代器
					Iterator<Map<String, Object>> authzMetadataIterator = authzResource.iterator();
					// 遍历授权资源元数据
					while (authzMetadataIterator.hasNext()) {
						Map<String, Object> curAuthzMetadata = authzMetadataIterator.next();
						// 获取每条授权资源元数据角色信息
						String roleIdStr = curAuthzMetadata.get("roleId").toString();
						// 获得每条授权资源元数据资源信息集合
						@SuppressWarnings("unchecked")
						List<Map<String, String>> resources = (List<Map<String, String>>) curAuthzMetadata.get("resources");
						// 支持授权资源元数据角色集合，即roleId支持以“,”英文逗号分割的形式
						String[] roleIds = roleIdStr.split(",");
						for (String roleId : roleIds) {
							// 判断用户角色是否有权限
							if (curUseRoleId.equals(roleId)) {
								// 判断类型
								list.addAll(resources);
							}
						}
					}
				}
				// 获得指定类型的当前登录用户有权限的资源信息
				if (!"".equals(type) && null != type) {
					Iterator<Map<String, String>> listIterator = list.iterator();
					while (listIterator.hasNext()) {
						if (!type.equals(listIterator.next().get("type"))) {
							listIterator.remove();
						}
					}
				}
			}
		} 
		return list;
	}
}
