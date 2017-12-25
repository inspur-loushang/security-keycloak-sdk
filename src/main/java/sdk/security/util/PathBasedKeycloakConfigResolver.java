package sdk.security.util;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringBufferInputStream;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.spi.HttpFacade.Cookie;

import com.google.gson.Gson;

/**
 * Resolve configuration of Keycloak
 * 
 * @author Data Security Group
 *
 */
@SuppressWarnings("deprecation")
public class PathBasedKeycloakConfigResolver implements KeycloakConfigResolver {
	
	private final Map<String, KeycloakDeployment> cache = new ConcurrentHashMap<String, KeycloakDeployment>();

	public static KeycloakDeployment nowDeployment = null;
	
	@Override
	public KeycloakDeployment resolve(OIDCHttpFacade.Request request) {
		String realm =null;
        String path = request.getURI();
        /*int multitenantIndex = path.indexOf("home/");
        if (multitenantIndex > -1) {
	        realm = path.substring(path.indexOf("home/")).split("/")[1];
	        if (realm.contains("?")) {
	            realm = realm.split("\\?")[0];
	        }
        }*/
        
        int multitenantIndex = path.indexOf("?realm=");
        if (multitenantIndex > -1) {
	        realm = path.substring(multitenantIndex).split("=")[1];
	        if (realm.contains("&")) {
	            realm = realm.split("&")[0];
	        }
        }
        
        if(realm == null) {
        	Cookie mtCookie = request.getCookie("mt");
        	realm = mtCookie.getValue();
        }
        
        if(realm == null) {
        	throw new IllegalStateException("Not able to resolve realm from the request path!");
        }
        
        KeycloakDeployment deployment = cache.get(realm);
        nowDeployment = deployment;
        if (null == deployment) {
            // not found on the simple cache, try to load it from the file system
            //InputStream is = getClass().getResourceAsStream("/" + realm + "-keycloak.json");
            InputStream is = getClass().getResourceAsStream("/keycloak.json");
            if (is == null) {
                throw new IllegalStateException("Not able to find the file keycloak.json");
            }
            
            try {
            	// change realm and auth-server-url
    			Reader reader = new InputStreamReader(is, "UTF-8");
    			Map map = new Gson().fromJson(reader, Map.class);
//    			String realmStr = map.get("realm").toString();
//    			System.out.println(realmStr);
    			
    			map.put("realm", realm);
//    			JSONObject jsonObject = JSONObject.fromObject(map);
    			String config = new Gson().toJson(map);
    			is = new StringBufferInputStream(config);

    		} catch (UnsupportedEncodingException e) {
    			e.printStackTrace();
    		}
            
            deployment = KeycloakDeploymentBuilder.build(is);
            cache.put(realm, deployment);
            nowDeployment = deployment;
        }
        
        return deployment;
	}

}
