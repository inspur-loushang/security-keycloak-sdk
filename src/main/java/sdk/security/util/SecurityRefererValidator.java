package sdk.security.util;

import java.text.MessageFormat;

import javax.servlet.http.HttpServletRequest;

public class SecurityRefererValidator {

	private String[] getTrustReferers() {
		String[] referers = new String[] {};
		String userHide = PropertiesUtilEnhance.getValue("conf.properties", "security.referer");
		if (!StringUtil.isEmptyString(userHide)) {
			referers = userHide.split(";");
		}

		return referers;
	}
	
	private String getIPFromRequestUrl (String url) {
		String ip = null;
		if (url.startsWith("http://") || url.startsWith("https://")) {
			url = url.substring(url.indexOf("://") + 3);
			url = url.substring(0, url.indexOf("/"));
			if (url.contains(":")) {
				url = url.split(":")[0];
			}
		}
		ip = url;
		return ip;
	}

	public boolean isTrustReferer(HttpServletRequest request) {
		boolean trusted = false;
		String[] trustReferers = getTrustReferers();
		
		// 未配置可信referer，则不校验
		if(trustReferers.length == 0) {
			String requestURL = request.getRequestURL().toString();
			String ip = getIPFromRequestUrl(requestURL);
			if(StringUtil.isEmptyString(ip)) {
				return true;
			} else {
				trustReferers = new String[1];
				trustReferers[0] = ip;
				System.out.println(MessageFormat.format("no conf referer, get from requesturl {0}", ip));
			}
		}

		String referer = request.getHeader("referer");

		if (StringUtil.isEmptyString(referer)) {
			return true;
		}else {

			// 获取IP
			referer = getIPFromRequestUrl(referer);

			for (String reg : trustReferers) {
				if (referer !=null && referer.matches(reg)) {
					trusted = true;
					break;
				}
			}
		}
		
		if(!trusted) {
			System.out.println(MessageFormat.format("{0} is untrusted where access {1}",
					referer, request.getRequestURL().toString()));
		}
		
		return trusted;
	}

	public static void main(String[] args) {
		boolean trusted = false;
		String[] trustReferers = new String[] { "10.110.13.127", "10.110.13.*" };

		String[] referers = new String[] { "http://10.110.13.127/indata-dev-portal/?realm=realm1234",
				"http://10.110.13.127:9000/indata-dev-portal/?realm=realm1234",
				"https://10.110.13.127:9000/indata-dev-portal/?realm=realm1234",
				"10.110.13.127", "10.110.13.128",
				"10.11.13.128" };
		
		for (String referer : referers) {
			System.out.println(referer);
			if (referer.startsWith("http://") || referer.startsWith("https://")) {
				referer = referer.substring(referer.indexOf("://") + 3);
				referer = referer.substring(0, referer.indexOf("/"));
				if (referer.contains(":")) {
					referer = referer.split(":")[0];
				}
			}

			for (String reg : trustReferers) {

				System.out.println(MessageFormat.format("{0}, {1}, {2}", referer, reg, referer.matches(reg)));
			}
		}

	}

}
