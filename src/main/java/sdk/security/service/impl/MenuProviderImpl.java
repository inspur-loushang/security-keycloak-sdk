package sdk.security.service.impl;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.IOUtils;

import sdk.security.authz.AuthorizationProvider;
import sdk.security.menu.data.Menu;
import sdk.security.service.IMenuProvider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class MenuProviderImpl implements IMenuProvider {

	private static final String menuFile = "securitySDKMenu.json";

	/**
	 * 获取当前登录用户有权限的菜单
	 * 
	 * @param parentId[父级菜单id,可以为空]
	 * @return
	 */
    @SuppressWarnings("unchecked")
	public String getAuthzMenu(String parentId) {

		List<Menu> dirSubMenus = getMenuWithBean(parentId);
	    List<Menu> menus = new ArrayList<Menu>();
		// 权限过滤
		if (dirSubMenus != null && !dirSubMenus.isEmpty()) {
			for (Menu authm : dirSubMenus) {
				boolean hasPermission = AuthorizationProvider.hasPermission(authm.getId());
				if (hasPermission) {
				    menus.add(authm);
				}
			}
		}
		Gson gson = new Gson();
	    return gson.toJson(menus);
	}

	/**
	 * 获取菜单
	 * 
	 * @param parentId[父级菜单id,可以为空]
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public List<Menu> getMenuWithBean(String parentId) {

		List<Menu> dirSubMenus = new ArrayList<Menu>();
		// 读取菜单json文件获得所有菜单
		List<Menu> allMenus = fromJson();
		// 根据父级菜单id获取直接下级菜单，顶级菜单时父级菜单id可以是null或者""
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("pId", parentId);
		getDirectSubMenu(map, allMenus);
		dirSubMenus = (List<Menu>) map.get("dirSubMenus");

		return dirSubMenus;
	}
	
	   /**
     * 获取菜单
     * 
     * @param parentId[父级菜单id,可以为空]
     * @return
     */
    @SuppressWarnings("unchecked")
    public String getMenu(String parentId) {
        List<Menu> list = getMenuWithBean(parentId);
        
        Gson gson = new Gson();
        return gson.toJson(list);
    }

	private void getDirectSubMenu(Map<String, Object> map, List<Menu> menus) {

		List<Menu> dirSubMenu = new ArrayList<Menu>();

		for (Menu menu : menus) {
			if (!"".equals(map.get("pId")) && map.get("pId") != null) {
				String parentMenuId = map.get("pId").toString();
				if (menu.getId().equals(parentMenuId)) {
					// 过滤掉孙子菜单
					if (menu.getChildren() != null && !menu.getChildren().isEmpty()) {
						for (Menu smeun : menu.getChildren()) {
							smeun.setChildren(null);
							dirSubMenu.add(smeun);
						}
					}
					map.put("dirSubMenus", dirSubMenu);
					break;
				}
				List<Menu> children = menu.getChildren();
				if (children != null && !children.isEmpty()) {
					getDirectSubMenu(map, children);
				}
			} else {
				menu.setChildren(null);
				dirSubMenu.add(menu);
				map.put("dirSubMenus", dirSubMenu);
			}
		}
	}

	/**
	 * 从JSON文件中获取菜单数据
	 * 
	 * @return
	 */
	private List<Menu> fromJson() {
		List<Menu> menus = new ArrayList<Menu>();
		String json = null;

		InputStream in = null;
		ClassLoader ccl = MenuProviderImpl.class.getClassLoader();
		in = ccl.getResourceAsStream(menuFile);
		try {
			json = IOUtils.toString(in, "utf-8");
		} catch (IOException e) {
			e.printStackTrace();
		}

		Gson gson = new Gson();
		JsonParser parser = new JsonParser();
		JsonObject jsonObject = parser.parse(json).getAsJsonObject();
		JsonArray jsonArray = parser.parse(jsonObject.get("menu").toString()).getAsJsonObject().getAsJsonArray("rows");

		for (int i = 0; i < jsonArray.size(); i++) {
			JsonElement el = jsonArray.get(i);
			Menu data = gson.fromJson(el, Menu.class);
			menus.add(data);
		}
		return menus;
	}
}
