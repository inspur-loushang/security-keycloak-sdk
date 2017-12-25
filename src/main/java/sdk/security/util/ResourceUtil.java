package sdk.security.util;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.IOUtils;

import com.google.gson.Gson;

@SuppressWarnings("unchecked")
public class ResourceUtil {
	
	private static List<Map<String, Object>> authzResource;

	static {
		List<Map<String, Object>> list = new ArrayList<Map<String, Object>>();
		try {
			ClassLoader ccl = ResourceUtil.class.getClassLoader();
			InputStream inputInner = ccl.getResourceAsStream("securitySDKAuthz.json");
			String jsonString = IOUtils.toString(inputInner, "UTF-8");
			Gson gson = new Gson();
			list = gson.fromJson(jsonString, List.class);
		} catch (Exception e) {
			authzResource = list;
		}
		authzResource = list;
	}

	/**
	 * 获取授权元数据
	 * 
	 * @return
	 */
	public static List<Map<String, Object>> getAuthzResource() {

		return authzResource;
	}
}
