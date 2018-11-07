package sdk.security.util;

import java.text.MessageFormat;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.MySQLCodec;
import org.owasp.esapi.codecs.MySQLCodec.Mode;

public class SecurityHttpServletRequestWrapper extends HttpServletRequestWrapper {

	public SecurityHttpServletRequestWrapper(HttpServletRequest request) {
		super(request);
	}

	public String[] getParameterValues(String parameter) {
		String[] values = super.getParameterValues(parameter);
		if (values == null) {
			return null;
		}
		int count = values.length;
		String[] encodedValues = new String[count];
		for (int i = 0; i < count; i++) {
			encodedValues[i] = process(values[i]);
		}
		return encodedValues;
	}

	@Override
	public String getParameter(String parameter) {
		String value = super.getParameter(parameter);
		if (value == null) {
			return null;
		}
		return process(value);
	}

	@Override
	public Object getAttribute(String name) {
		Object value = super.getAttribute(name);
		if (null != value && value instanceof String) {
			value = process((String) value);
		}
		return value;
	}

	@Override
	public String getHeader(String name) {

		String value = super.getHeader(name);
		if (value == null)
			return null;
		return process(value);
	}

	private String process(String value) {
		String ret =  cleanXSS(value);
		return ret;
	}

	private String encodeForSQL(String value) {
		return ESAPI.encoder().encodeForSQL(new MySQLCodec(Mode.STANDARD), value);
	}
	
	private String encodeForJS(String value) {
		return ESAPI.encoder().encodeForJavaScript(value);
	}

	private String encodeForHTML(String value) {
		return ESAPI.encoder().encodeForHTML(value);
	}
	
	private String cleanXSS(String paramString) {
		if (paramString == null)
			return "";
		String str = paramString;
		str = str.replaceAll("", "");
		Pattern localPattern = Pattern.compile("<script>(.*?)</script>", 2);
		str = localPattern.matcher(str).replaceAll("");
		localPattern = Pattern.compile("src[\r\n]*=[\r\n]*\\'(.*?)\\'", 42);
		str = localPattern.matcher(str).replaceAll("");
		localPattern = Pattern.compile("src[\r\n]*=[\r\n]*\\\"(.*?)\\\"", 42);
		str = localPattern.matcher(str).replaceAll("");
		localPattern = Pattern.compile("</script>", 2);
		str = localPattern.matcher(str).replaceAll("");
		localPattern = Pattern.compile("<script(.*?)>", 42);
		str = localPattern.matcher(str).replaceAll("");
		localPattern = Pattern.compile("eval\\((.*?)\\)", 42);
		str = localPattern.matcher(str).replaceAll("");
		localPattern = Pattern.compile("expression\\((.*?)\\)", 42);
		str = localPattern.matcher(str).replaceAll("");
		localPattern = Pattern.compile("javascript:", 2);
		str = localPattern.matcher(str).replaceAll("");
		localPattern = Pattern.compile("vbscript:", 2);
		str = localPattern.matcher(str).replaceAll("");
		localPattern = Pattern.compile("onload(.*?)=", 42);
		str = localPattern.matcher(str).replaceAll("");
		str = str.replaceAll("\\(", "&#40;").replaceAll("\\)", "&#41;");
		str = str.replaceAll("'", "&#39;");
		str = str.replaceAll("<", "&lt;").replaceAll(">", "&gt;");
		str = str.replaceAll("\\+", "&#x2b;");
		
		if(!paramString.equals(str)) {
			System.out.println(MessageFormat.format("value {0}, after xss clean {1}", paramString, str));
		}
		return str;
	}
	
}
