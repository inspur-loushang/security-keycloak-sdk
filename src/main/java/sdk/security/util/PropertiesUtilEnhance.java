package sdk.security.util;

import java.io.File;
import java.net.URL;

/**
 * 增强 {@link PropertiesUtil},
 * 
 * @author Data Security Group
 *
 */
public class PropertiesUtilEnhance {

	private static String prePrecessFileName(String filename) {
		String filenameProcessed = filename;
		if (filename != null && filename.startsWith("/")) {
			filenameProcessed = filename.substring(1);
		}
		return filenameProcessed;
	}

	private static boolean isFileExist(String filename) {
		ClassLoader classLoader = PropertiesUtilEnhance.class.getClassLoader();
		URL url = classLoader.getResource("/");
		if(url == null) {
			return false;
		}
		String path = url.getPath();
		File f = new File(path+filename);
		boolean exist = f.exists();
		return exist;
	}

	public static String getValue(String filename, String key) {
		String value = null;
		String filenameProcessed = prePrecessFileName(filename);
		if (isFileExist(filenameProcessed)) {
			value = PropertiesUtil.getValue(filenameProcessed, key);
		}
		return value;
	}

	public static String getValue(String filename, String key, String defaultValue) {
		String value = defaultValue;
		String filenameProcessed = prePrecessFileName(filename);
		if (isFileExist(filenameProcessed)) {
			value = PropertiesUtil.getValue(filenameProcessed, key, defaultValue);
		}
		return value;
	}
}
