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

public class SDKFilter implements Filter {

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
		
		filterChain.doFilter(request, response);
	}

	public void init(FilterConfig filterConfig) throws ServletException {

	}

}
