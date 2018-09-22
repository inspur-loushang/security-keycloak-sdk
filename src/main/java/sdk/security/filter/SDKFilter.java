package sdk.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import sdk.security.authc.AuthenticationProvider;
import sdk.security.util.HttpServletThreadLocal;
import sdk.security.util.SecurityHttpServletRequestWrapper;
import sdk.security.util.SecurityRefererValidator;
import sdk.security.util.StringUtil;

public class SDKFilter implements Filter {
	private boolean securityRequestWrapper;
	private boolean securityRefererValidator;
	private String[] securityRequestWrapperExcludes = new String[] {};

	public void init(FilterConfig filterConfig) throws ServletException {
		securityRequestWrapper = 
				"false".equals(filterConfig.getInitParameter("securityRequestWrapper"))? false: true;
		securityRefererValidator = 
				"false".equals(filterConfig.getInitParameter("securityRefererValidator"))? false: true;
		String excludesParameter = filterConfig.getInitParameter("securityRequestWrapperExcludes");
		if (!StringUtil.isEmptyString(excludesParameter)) {
			securityRequestWrapperExcludes = excludesParameter.split(";");
		}
	}
	
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
		//将HttpServletRequest对象放到线程变量中
		HttpServletThreadLocal.clearRequest();
		HttpServletThreadLocal.setRequest(request);
		//将用户标识放到session中
		HttpSession session = request.getSession();
		String userId = null;
		try {
			userId = AuthenticationProvider.getLoginUserId();
		} catch (Exception e) {
			userId = "";
		}
		session.setAttribute("userId", userId);
		
		
		if(securityRequestWrapper && !isSecurityRequestWrapperExcludes(request)) {
			request = new SecurityHttpServletRequestWrapper(request);
		}
		
		if(securityRefererValidator) {
			SecurityRefererValidator srv = new SecurityRefererValidator();
			if(!srv.isTrustReferer(request)) {
				response.setStatus(403);
				return;
			}
		}

		filterChain.doFilter(request, response);
	}

	private boolean isSecurityRequestWrapperExcludes(HttpServletRequest request) {
		boolean result = false;
		String requestUrl = request.getRequestURL().toString();
		if (this.securityRequestWrapperExcludes.length != 0) {
			for (String url : securityRequestWrapperExcludes) {
				if (requestUrl.matches(url)) {
					result = true;
					break;
				}
			}
		}
		return result;
	}
	
}
