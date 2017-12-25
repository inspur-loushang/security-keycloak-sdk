package sdk.security.filter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import sdk.security.authz.AuthorizationProvider;

public class SDKAuthzFilter implements Filter {

	public void destroy() {
	}

	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
			throws IOException, ServletException {

		if (!(servletRequest instanceof HttpServletRequest)) {
			throw new ServletException("Only Support HttpServletRequest");
		}

		if (!(servletResponse instanceof HttpServletResponse)) {
			throw new ServletException("Only Support HttpServletResponse");
		}
		doFilterAuthz((HttpServletRequest) servletRequest, (HttpServletResponse) servletResponse, filterChain);
	}

	private void doFilterAuthz(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {
		String requestUrl = request.getRequestURL().toString();
		List<Map<String, String>> list = AuthorizationProvider.getResources(null);
		boolean authz = false;
		if (!list.isEmpty()) {
			for (Map<String, String> map : list) {
				String regex = map.get("url");
				Pattern pattern = Pattern.compile(regex);
				Matcher matcher = pattern.matcher(requestUrl);
				authz = matcher.find();
				if (authz) {
					break;
				} else {
					continue;
				}
			}
		} else {
			authz = true;
		}
		if (authz) {
			filterChain.doFilter(request, response);
		} else {
			return;
		}
	}

	public void init(FilterConfig filterConfig) throws ServletException {

	}
}
