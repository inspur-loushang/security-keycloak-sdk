package sdk.security.util;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.text.MessageFormat;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.spi.HttpFacade.Cookie;
import org.keycloak.adapters.spi.HttpFacade.Request;
import org.keycloak.constants.AdapterConstants;

import com.google.gson.Gson;

/**
 * Resolve configuration of Keycloak
 * 
 * @author Data Security Group
 *
 */
public class PathBasedKeycloakConfigResolver implements KeycloakConfigResolver {
	private Log logger = LogFactory.getLog(PathBasedKeycloakConfigResolver.class);

	private final Map<String, KeycloakDeployment> cache = new ConcurrentHashMap();
	
	@Deprecated	
	public static KeycloakDeployment nowDeployment = null;
	
	public KeycloakDeployment resolve(Request request) {
		String realm = null;
		String cluster = null;
		KeycloakDeployment deployment = null;
		String path = request.getURI();
		
		// get realm from request
		realm = getValueFromRequestUrlAndReferer("realm", request);
		
		// get cluster from request
		cluster = getValueFromRequestUrlAndReferer("cluster", request);
		
		// get cluster from cookie
		Cookie clusterCookie = request.getCookie(SecurityConstant.CLUSTER_ID_COOKIE_NAME);
		if (cluster == null && clusterCookie != null) {
			cluster = clusterCookie.getValue();
		}
		
		// get realm from cookie that it's name is in keycloak.json
		if (realm == null) {
			String realmConf = getRealmFromKeycloakJson();
			
			if (!StringUtil.isEmptyString(realmConf)) {
				// realm like ${cookie.MY_COOKIE_VARIABLE}
				Pattern pattern = Pattern.compile("\\$\\{cookie\\.(.*)\\}");
				Matcher m = pattern.matcher(realmConf);
				if(m.find()) {
					String cookieName = m.group(1);
					Cookie mtCookie = request.getCookie(cookieName);
					if (mtCookie != null) {
						realm = mtCookie.getValue();
					}
				} else {
					realm = realmConf;
				}
			}
		}

		if(realm == null && cluster != null && !ClusterInfoUtil.isClusterQueryUrl(path)) {
			Map<String, String> clusterInfo = ClusterInfoUtil.getClusterInfoByClusterId(cluster);
			if (clusterInfo != null) {
				realm = clusterInfo.get("realm");
			}
		}

		// get all clusters of platform, or get all clusters of one realm, and get realm if have only one realm
		if(cluster == null && !ClusterInfoUtil.isClusterQueryUrl(path)) {
			List allClusters = null; 
			if(realm == null) {
				allClusters = ClusterInfoUtil.getAllClusters();
			} else {
				allClusters = ClusterInfoUtil.getRealmClusters(realm);
			}
			Set<String> set = new HashSet<String>();
			
			if(allClusters!=null && allClusters.size()>0) {
				for(int i=0, length=allClusters.size(); i<length; i++) {
					Map m = (Map) allClusters.get(i);
					String r = (String) m.get("realm");
					if(r!=null) {
						set.add(r);
					}
					// 获取第一个集群
					if(cluster == null) {
						cluster = (String) m.get("clusterId");
					}
				}
			}
			
			if(realm == null && set.size() == 1) {
				Iterator<String> iterator = set.iterator();
				realm = iterator.next();
				
			}
		}
		
		// 先将cluster和realm写入线程变量，SDKFilter中将cluster detail写入会话
		if (cluster != null) {
			HttpServletThreadLocal.setSecurityContext(SecurityConstant.CLUSTER_ID_SESSION_KEY, cluster);
		}
		 
		// get realm from static variable named cache
		if(realm == null && cache.get("master") != null && cache.size() == 1) {
			realm = "master";
		}
		
		/* 
		 * TODO 验证从cache中判断后，是否还需要从logout url中获取；
		 * 验证多租户tenant的退出是否有效且不影响其他tenant
		 */
		if (realm == null) {
			realm = getRealmNameForLogout(path);
		}
		
		if (realm == null) {
			realm = "master";
		}

		if(deployment == null) {
			deployment = this.cache.get(realm);
		}

		if (deployment == null) {
			deployment = init(realm, request, true);
		} else {
			deployment = updateKeycloakDeployment(deployment, request);
		}
		
		/*
		 * 以下情况auth-server-url使用keycloak.json
		 * 1. 请求带有state和code参数时，应用后台(Tomcat)向keycloak发起code置换token的请求
		 * 2. 请求以k_logout结尾，keycloak向应用后台发起注销请求，直到整个退出流程完成，都是后台在交互
		 */
		// 
		if(path.contains("state=") && path.contains("code=") || 
				path.endsWith(AdapterConstants.K_LOGOUT)) {
			deployment = init(realm, request, false);
		}
		
		this.cache.put(realm, deployment);
		
		nowDeployment = deployment;
		return deployment;
	}
	
	private String getValueFromRequestUrlAndReferer(String key, Request request) {
		/* 
		 * e.g. ?realm=
		 * e.g. ?cluster=
		*/
		String param = MessageFormat.format("?{0}=", key);
		String path = request.getURI();
		String value = null;
		
		// get realm/cluster from request url
		int multitenantIndex = path.indexOf(param);
		if (multitenantIndex > -1) {
			value = path.substring(multitenantIndex).split("=")[1];
			if (value.contains("&")) {
				value = value.split("&")[0];
			}
		}
		
		// get realm/cluster from request Referer Header
		if(value == null) {
			String referer = request.getHeader("Referer");
			if(referer!=null && referer.contains(param)) {
				int refererMultitenantIndex = referer.indexOf(param);
				value = referer.substring(refererMultitenantIndex).split("=")[1];
				if (value.contains("&")) {
					value = value.split("&")[0];
				}
			}
		}
		
		return value;
	}
	
	// get realm from keycloak.json in app.war
	private String getRealmFromKeycloakJson() {
		String realm = null;
		InputStream is = getClass().getResourceAsStream("/keycloak.json");
		if (is == null) {
			throw new IllegalStateException("Not able to find the file keycloak.json");
		}

			try {
				Reader reader = new InputStreamReader(is, "UTF-8");
				Map map = (Map) new Gson().fromJson(reader, Map.class);
				realm = (String) map.get("realm");
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}

		return realm;
	}
	
	// get KeycloakDeployment from keycloak.json in app.war
	private KeycloakDeployment getFromKeycloakJson() {

		InputStream is = getClass().getResourceAsStream("/keycloak.json");
		if (is == null) {
			throw new IllegalStateException("Not able to find the file keycloak.json");
		}

		try {
			Reader reader = new InputStreamReader(is, "UTF-8");
			Map map = (Map) new Gson().fromJson(reader, Map.class);
			String config = new Gson().toJson(map);
			is = new ByteArrayInputStream(config.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}

		KeycloakDeployment deployment = KeycloakDeploymentBuilder.build(is);
		return deployment;
	}
	
	/**
	 * 初始化KeycloakDeployment
	 * 
	 * @param realm
	 * @param request 不为NULL时，处理auth-serve-url
	 * @return
	 */
	private KeycloakDeployment init(String realm, Request request, boolean checkNetwork) {

		InputStream is = getClass().getResourceAsStream("/keycloak.json");
		if (is == null) {
			throw new IllegalStateException("Not able to find the file keycloak.json");
		}

		try {
			Reader reader = new InputStreamReader(is, "UTF-8");
			Map map = (Map) new Gson().fromJson(reader, Map.class);
			map.put("realm", realm);

			String authServerConf = (String) map.get("auth-server-url");
			if(isInExtNetwork() && request != null && checkNetwork) {
				authServerConf = processAuthServerUrl(authServerConf, request);
			}

			String scheme = getScheme(request);
			if("https".equalsIgnoreCase(scheme) && authServerConf.toLowerCase().startsWith("http:")) {
				authServerConf = authServerConf.replace("http:", "https:");
				authServerConf = processHttpsAuthServerUrl(authServerConf);
			}
			map.put("auth-server-url", authServerConf);
			
			String config = new Gson().toJson(map);
			is = new ByteArrayInputStream(config.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}

		KeycloakDeployment deployment = KeycloakDeploymentBuilder.build(is);
		
		return deployment;
	}
	
	// deployment中的IP与Request中不同时，更新deployment
	private KeycloakDeployment updateKeycloakDeployment(KeycloakDeployment deployment,
			Request request) {
		KeycloakDeployment newDeployment = deployment;
		if(isInExtNetwork()) {
			String hostName = getServerFromRequest(request);
			if (!deployment.getAuthServerBaseUrl().contains(hostName)) {
				newDeployment = init(deployment.getRealm(), request, true);
			}
		}
		
		String scheme = getScheme(request);
		String authServerConf = newDeployment.getAuthServerBaseUrl();
		if("https".equalsIgnoreCase(scheme) && authServerConf.toLowerCase().startsWith("http:")) {
			newDeployment = init(deployment.getRealm(), request, true);
		}
		
		if("http".equalsIgnoreCase(scheme) && authServerConf.toLowerCase().startsWith("https:")) {
			newDeployment = init(deployment.getRealm(), request, true);
		}
		
		return newDeployment;
	}
	
	// get IP or hostname
	private String getServerFromRequest(Request request) {
		String hostHeader = request.getHeader("Host");
		String hostName = null;

		if (hostHeader != null) {
			if (hostHeader.contains(":")) {
				String[] hostSplit = hostHeader.split(":");
				hostName = hostSplit[0];
			} else {
				hostName = hostHeader;
			}
		}
		return hostName;
	}
	
	private String processAuthServerUrl(String authServerConf, Request request) {
		// 如果配置文件中Keycloak地址与用户访问地址不同，则可能为内外网环境，使用访问地址替换
		String newAuthServerConf = authServerConf;
		String hostName = getServerFromRequest(request);
		if (authServerConf != null && !authServerConf.contains(hostName)) {
			String reg = "";
			StringBuffer replacement = new StringBuffer();
			replacement.append("//");
			replacement.append(hostName);

			String port = getKeycloakPort();
			if (StringUtil.isEmptyString(port)) {
				reg = "\\/\\/([^\\/\\:]*)";
			} else {
				reg = "\\/\\/([^\\/\\/]*)";
				if (!"80".equals(port)) {
					replacement.append(":");
					replacement.append(port);
				}
			}
			newAuthServerConf = authServerConf.replaceFirst(reg, replacement.toString());
		}
		return newAuthServerConf;
	}
	
	// 判断是否处理内外网
	private boolean isInExtNetwork() {
		String network = PropertiesUtilEnhance.getValue("conf.properties", "network.in-external");
		return "true".equals(network);
	}
	
	private String getKeycloakPort() {
		String port = PropertiesUtilEnhance.getValue("conf.properties", "network.keycloak.port");
		return port;
	}
	
	private String getRealmNameForLogout(String url) {
		String realm = null;
		int index1 = url.lastIndexOf("k_logout");
		if (index1 > 0) {
			try {
				String urla = url.substring(0, index1 - 1);
				int index2 = urla.lastIndexOf("/");
				realm = urla.substring(index2 + 1, urla.length());
			} catch (Exception e) {
				this.logger.error("get realm fails for client logout, error info ", e);
				e.printStackTrace();
			}
		}
		return realm;
	}
	
	private String getScheme(Request request) {
		//String scheme = request.getHeader("X-Forwarded-Proto");
		String uri = request.getURI();
		String scheme = uri.substring(0, uri.indexOf("://"));
		return scheme;
	}
	
	private String getHttpsServerPort() {
		String port = "29080";
		String portConf = PropertiesUtilEnhance.getValue("conf.properties", "https.keycloak.port");
		
		if(!StringUtil.isEmptyString(portConf)) {
			port = portConf;
		}
		return port;
	}
	
	private String processHttpsAuthServerUrl(String authServerConf) {
		String newAuthServerUrl = authServerConf;
		
		String[] parts = authServerConf.split("/");
		if(parts != null && parts.length == 4) {
			String ipAndPort = parts[2];
			String ip = ipAndPort;
			if(ipAndPort.contains(":")) {
				ip = ipAndPort.split(":")[0];
			}
			StringBuffer sr = new StringBuffer();
			sr.append(parts[0]);
			sr.append("//");
			sr.append(ip);
			sr.append(":");
			sr.append(getHttpsServerPort());
			sr.append("/");
			sr.append(parts[3]);
			newAuthServerUrl = sr.toString();
		}
		
		return newAuthServerUrl;
	}
	
}