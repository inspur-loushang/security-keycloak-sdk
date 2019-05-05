package sdk.security.util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import sdk.security.service.impl.SecurityProviderImpl;

public class ClusterInfoUtil {
	
	private static final String ALL_CLUSTERE_NDPOINT = "/manage-cluster/service/indata/cluster/instances";
	private static final String CLUSTER_ENDPOINT =
			"/manage-cluster/service/indata/cluster/getInstanceByClusterName";
	private static final String REALM_CLUSTERS_ENDPOINT =
			"/manage-cluster/service/indata/cluster/clusterInfos/{realm}";
	
	/**
	 * get cluster info
	 * 
	 * @param clusterId
	 * @return Map, key:clusterId, clusterName, realm
	 */
	public static Map<String, String> getClusterInfoByClusterId(String clusterId) {
		
		StringBuffer sr = new StringBuffer();
		sr.append(new SecurityProviderImpl().getManagePortalServer());
		sr.append(CLUSTER_ENDPOINT);
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
		sr.append(ALL_CLUSTERE_NDPOINT);
		
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
	
	public static List getRealmClusters(String realm) {
		StringBuffer sr = new StringBuffer();
		sr.append(new SecurityProviderImpl().getManagePortalServer());
		sr.append(REALM_CLUSTERS_ENDPOINT);
		
		Map<String, String> uriVariables = new HashMap<String, String>();
		uriVariables.put("realm", realm);
		
		List clusters = 
				RestRequestUtils.get(sr.toString(), List.class, uriVariables, null, null);
		return clusters;
	}
	
	public static boolean isClusterQueryUrl(String requestUrl) {
		return (requestUrl.indexOf(ALL_CLUSTERE_NDPOINT) > 0 || requestUrl.indexOf(CLUSTER_ENDPOINT) > 0
				|| requestUrl.indexOf(REALM_CLUSTERS_ENDPOINT) > 0);
	}

}
