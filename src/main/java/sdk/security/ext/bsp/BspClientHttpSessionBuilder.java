package sdk.security.ext.bsp;

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

import org.loushang.bsp.agent.context.AgentBspInfoImpl;

import sdk.security.authc.AuthenticationProvider;
import sdk.security.util.StringUtil;

/**
 * 适配BSP的会话存储格式
 * 
 */
public class BspClientHttpSessionBuilder implements Filter{

	/**
	 * 用来保证该过滤器每次请求只执行一次的参数设置
	 */
	private static final String FILTER_APPLIED = "__securitysdk_bspclient_sessionbuilder";
	private final String SECURITY_CONTECT_KEY = "UserLoginInfo";
	
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		if (!(request instanceof HttpServletRequest)) {
			throw new ServletException("Only Support HttpServletRequest");
		}

		if (!(response instanceof HttpServletResponse)) {
			throw new ServletException("Only Support HttpServletResponse");
		}
		
		doFilterHttp((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}
	
	private void doFilterHttp(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {

		if (request.getAttribute(FILTER_APPLIED) != null) {
			filterChain.doFilter(request, response);
			return;
		}
		
		String userId = AuthenticationProvider.getLoginUserId();
		if(!StringUtil.isEmptyString(userId)) {
			AgentBspInfoImpl bspInfo = new AgentBspInfoImpl();
			bspInfo.setUserId(userId);
			bspInfo.setUserName(userId);
			HttpSession session = request.getSession();
			session.setAttribute(SECURITY_CONTECT_KEY, bspInfo);
		}
		
		filterChain.doFilter(request, response);
	}

	@Override
	public void destroy() {
		
	}

}
