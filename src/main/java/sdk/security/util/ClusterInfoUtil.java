package sdk.security.util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import sdk.security.service.impl.SecurityProviderImpl;

public class ClusterInfoUtil {
	
	private static final String allClusterEndpoint = "/manage-cluster/service/indata/cluster/instances";
	private static final String clusterEndpoint =
			"/manage-cluster/service/indata/cluster/getInstanceByClusterName";
	
	/**
	 * get cluster info
	 * 
	 * @param clusterId
	 * @return Map, key:clusterId, clusterName, realm
	 */
	public static Map<String, String> getClusterInfoByClusterId(String clusterId) {
		
		StringBuffer sr = new StringBuffer();
		sr.append(new SecurityProviderImpl().getManagePortalServer());
		sr.append(clusterEndpoint);
		sr.append("/{clusterId}");
		
		Map<String, String> uriVariables = new HashMap<String, String>();
		uriVariables.put("clusterId", clusterId);
		
		Map<String, String> clusterInfo = 
				RestRequestUtils.get(sr.toString(), Map.class, uriVariables, null, null);
		return clusterInfo;
	}
	
	public static List getAllClusters() {
		StringBuffer sr = new StringBuffer();
		sr.append(new SecurityProviderImpl().getManagePortalServer());
		sr.append(allClusterEndpoint);
		
		MultiValueMap<String, String> bodyVariables = new LinkedMultiValueMap<String, String>();
		bodyVariables.add("token", KeycloakUtil.impersonate());
		
		Map clusterInfo = 
				RestRequestUtils.post(sr.toString(), Map.class, null, bodyVariables, null);
		
		List clusters = null;
		if(clusterInfo!=null && clusterInfo.get("data")!=null) {
			clusters = (List) clusterInfo.get("data");
		}
		
		return clusters;
	}
	
	public static boolean isClusterQueryUrl(String requestUrl) {
		return (requestUrl.indexOf(allClusterEndpoint) > 0 || requestUrl.indexOf(clusterEndpoint) > 0);
	}

}
