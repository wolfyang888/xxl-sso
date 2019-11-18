package com.xxl.sso.server.controller;

import com.xxl.sso.core.conf.Conf;
import com.xxl.sso.core.login.SsoWebLoginHelper;
import com.xxl.sso.core.store.SsoLoginStore;
import com.xxl.sso.core.user.XxlSsoUser;
import com.xxl.sso.core.store.SsoSessionIdHelper;
import com.xxl.sso.server.core.model.UserInfo;
import com.xxl.sso.server.core.result.ReturnT;
import com.xxl.sso.server.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.UUID;

/**
 * sso server (for web)
 *
 * @author xuxueli 2017-08-01 21:39:47
 */
@Controller
public class WebController {

    @Autowired
    private UserService userService;

    @RequestMapping("/")
    public String index(Model model, HttpServletRequest request, HttpServletResponse response) {

        // login check
        XxlSsoUser xxlUser = SsoWebLoginHelper.loginCheck(request, response);

        if (xxlUser == null) {
            String requestType = request.getParameter(Conf.SSO_RES_TYPE);
            if(Conf.SSO_CODE.equals(requestType)){
                // the Authentication-code mode
                return "redirect:/grant";

            }else {
                // the name password mode
                return "redirect:/login";
            }
        } else {
            model.addAttribute("xxlUser", xxlUser);
            return "index";
        }
    }

    /**
     * Login page
     *
     * @param model
     * @param request
     * @return
     */
    @RequestMapping(Conf.SSO_LOGIN)
    public String login(Model model, HttpServletRequest request, HttpServletResponse response) {

        // login check
        XxlSsoUser xxlUser = SsoWebLoginHelper.loginCheck(request, response);

        if (xxlUser != null) {

            // success redirect
            String redirectUrl = request.getParameter(Conf.REDIRECT_URL);
            if (redirectUrl!=null && redirectUrl.trim().length()>0) {

                String sessionId = SsoWebLoginHelper.getSessionIdByCookie(request);
                String redirectUrlFinal = redirectUrl + "?" + Conf.SSO_SESSIONID + "=" + sessionId;;

                return "redirect:" + redirectUrlFinal;
            } else {
                return "redirect:/";
            }
        }

        model.addAttribute("errorMsg", request.getParameter("errorMsg"));
        model.addAttribute(Conf.REDIRECT_URL, request.getParameter(Conf.REDIRECT_URL));
        return "login";
    }

    /**
     * Login
     *
     * @param request
     * @param redirectAttributes
     * @param username
     * @param password
     * @return
     */
    @RequestMapping("/doLogin")
    public String doLogin(HttpServletRequest request,
                        HttpServletResponse response,
                        RedirectAttributes redirectAttributes,
                        String username,
                        String password,
                        String ifRemember) {

        boolean ifRem = (ifRemember!=null&&"on".equals(ifRemember))?true:false;

        // valid login
        ReturnT<UserInfo> result = userService.findUser(username, password);
        if (result.getCode() != ReturnT.SUCCESS_CODE) {
            redirectAttributes.addAttribute("errorMsg", result.getMsg());

            redirectAttributes.addAttribute(Conf.REDIRECT_URL, request.getParameter(Conf.REDIRECT_URL));
            return "redirect:/login";
        }

        // 1、make xxl-sso user
        XxlSsoUser xxlUser = new XxlSsoUser();
        xxlUser.setUserid(String.valueOf(result.getData().getUserid()));
        xxlUser.setUsername(result.getData().getUsername());
        xxlUser.setVersion(UUID.randomUUID().toString().replaceAll("-", ""));
        xxlUser.setExpireMinite(SsoLoginStore.getRedisExpireMinite());
        xxlUser.setExpireFreshTime(System.currentTimeMillis());


        // 2、make session id
        String sessionId = SsoSessionIdHelper.makeSessionId(xxlUser);

        // 3、login, store storeKey + cookie sessionId
        SsoWebLoginHelper.login(response, sessionId, xxlUser, ifRem);

        // 4、return, redirect sessionId
        String redirectUrl = request.getParameter(Conf.REDIRECT_URL);
        if (redirectUrl!=null && redirectUrl.trim().length()>0) {
            String redirectUrlFinal = redirectUrl + "?" + Conf.SSO_SESSIONID + "=" + sessionId;
            return "redirect:" + redirectUrlFinal;
        } else {
            return "redirect:/";
        }

    }

    /**
     * Logout
     *
     * @param request
     * @param redirectAttributes
     * @return
     */
    @RequestMapping(Conf.SSO_LOGOUT)
    public String logout(HttpServletRequest request, HttpServletResponse response, RedirectAttributes redirectAttributes) {

        // logout
        SsoWebLoginHelper.logout(request, response);

        redirectAttributes.addAttribute(Conf.REDIRECT_URL, request.getParameter(Conf.REDIRECT_URL));
        return "redirect:/login";
    }


    /**
     * Login page
     *
     * @param model
     * @param request
     * @return
     */
    @RequestMapping(Conf.SSO_GRANT)
    public String grant(Model model, HttpServletRequest request, HttpServletResponse response) {

        // login check
        XxlSsoUser xxlUser = SsoWebLoginHelper.loginCheck(request, response);

        if (xxlUser == null) {
            return "redirect:/login";
        }

        model.addAttribute("errorMsg", request.getParameter("errorMsg"));
        model.addAttribute(Conf.REDIRECT_URL, request.getParameter(Conf.REDIRECT_URL));
        return "grant";
    }

    @RequestMapping("/doGrant")
    public String doGrant(Model model,
                          HttpServletRequest request,
                          HttpServletResponse response,
                          RedirectAttributes redirectAttributes,
                          String agree
                          ){

        // login check
        XxlSsoUser xxlUser = SsoWebLoginHelper.loginCheck(request, response);
        if( xxlUser == null){
            model.addAttribute("errorMsg", request.getParameter("errorMsg"));
            model.addAttribute(Conf.REDIRECT_URL, request.getParameter(Conf.REDIRECT_URL));
            return "redirect:/login";
        }

        // get the client_id

        String client_id = request.getParameter(Conf.SSO_CLIENT_ID);
        if("".equals(client_id) || null == client_id){
//            client_id = xxlUser.getUserid();
            client_id = xxlUser.getUsername();

        }
//        String requestType = (String)request.getAttribute(Conf.SSO_RES_TYPE);
        String requestType = Conf.SSO_GRANT_REQUEST;
        boolean bAgree = (agree!=null && "on".equals(agree))?true:false;
        String scope = request.getParameter(Conf.SSO_SCOPE);
        String state = request.getParameter(Conf.SSO_STATE);

        if (xxlUser.getUsername().equals(client_id))
        {
            if( Conf.SSO_GRANT_REQUEST.equals(requestType) && bAgree ){
                String code = SsoWebLoginHelper.generateCode(request);
                String sessionId = SsoWebLoginHelper.getSessionIdByCookie(request);
                String redirectUrl = request.getParameter(Conf.REDIRECT_URL);
                String redirectUrlFinal = redirectUrl + "?" + Conf.SSO_CODE + "=" + code
                                                      + "&" + Conf.SSO_STATE + "=" + state
                                                      + "&" + Conf.SSO_SESSIONID + "=" + sessionId;
                return "redirect:" + redirectUrlFinal;
            }else{
                return "redirect:/";
            }

        }
        return "redirect:/";

    }

    @RequestMapping(Conf.SSO_URI_TOKEN)
    public String getToken(Model model, HttpServletRequest request, HttpServletResponse response){

        // login check
        XxlSsoUser xxlUser = SsoWebLoginHelper.loginCheck(request, response);
        if( xxlUser == null){
            model.addAttribute("errorMsg", request.getParameter("errorMsg"));
            model.addAttribute(Conf.REDIRECT_URL, request.getParameter(Conf.REDIRECT_URL));
            return "redirect:/login";
        }

        String client_id = request.getParameter(Conf.SSO_CLIENT_ID);
        if("".equals(client_id) || null == client_id){
//            client_id = xxlUser.getUserid();
            client_id = xxlUser.getUsername();

        }
        String grantType = request.getParameter(Conf.SSO_GRANT_TYPE);
        String code = request.getParameter(Conf.SSO_CODE);
        String redirectUrl = request.getParameter(Conf.REDIRECT_URL);

        if (xxlUser != null) {

            // success redirect
            if (redirectUrl!=null && redirectUrl.trim().length()>0) {

                if( SsoWebLoginHelper.verifyCode(request,code, redirectUrl) ){
                    String scope = SsoWebLoginHelper.getScope(request);
                    String token = SsoWebLoginHelper.generateToken(request);
                    String refresh_token = SsoWebLoginHelper.generateRefreshToken(request);
                    String redirectUrlFinal = redirectUrl+"?"+Conf.SSO_ACCESS_TOKEN+ "=" + token;
                    response.setHeader(Conf.SSO_ACCESS_TOKEN,token);
                    response.setHeader(Conf.SSO_TOKEN_TYPE,Conf.SSO_BEARER_TOKEN_TYPE);
                    response.setHeader(Conf.SSO_REFRESH_TOKEN,refresh_token);
                    response.setIntHeader(Conf.SSO_EXPIRES_IN,Conf.SSO_EXPIRES_IN_TIME);

                    return "redirect:" + redirectUrlFinal;
                }else {
                    return "redirect:/";
                }

            } else {
                return "redirect:/";
            }
        }

        model.addAttribute("errorMsg", request.getParameter("errorMsg"));
        model.addAttribute(Conf.REDIRECT_URL, request.getParameter(Conf.REDIRECT_URL));
        return "login";
    }

    @RequestMapping(Conf.SSO_URI_CHECK_TOKEN)
    public String checkToken(Model model, HttpServletRequest request, HttpServletResponse response){
        // login check
        XxlSsoUser xxlUser = SsoWebLoginHelper.loginCheck(request, response);
        if( xxlUser == null){
            model.addAttribute("errorMsg", request.getParameter("errorMsg"));
            model.addAttribute(Conf.REDIRECT_URL, request.getParameter(Conf.REDIRECT_URL));
            return "redirect:/login";
        }

        String client_id = request.getParameter(Conf.SSO_CLIENT_ID);
        if("".equals(client_id) || null == client_id){
//            client_id = xxlUser.getUserid();
            client_id = xxlUser.getUsername();

        }
        String token = request.getParameter(Conf.SSO_ACCESS_TOKEN);
        String redirectUrl = request.getParameter(Conf.REDIRECT_URL);

        if (xxlUser != null) {

            // success redirect
            if (redirectUrl!=null && redirectUrl.trim().length()>0) {

                if( SsoWebLoginHelper.verifyToken(request,token, redirectUrl) ){
                    String redirectUrlFinal = redirectUrl;
                    return "redirect:" + redirectUrlFinal;
                }else {
                    return "redirect:/";
                }

            } else {
                return "redirect:/";
            }
        }

        model.addAttribute("errorMsg", request.getParameter("errorMsg"));
        model.addAttribute(Conf.REDIRECT_URL, request.getParameter(Conf.REDIRECT_URL));
        return "login";

    }


    }