package context

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/silenceper/wechat/util"
)

const (
	componentAccessTokenURL = "https://api.weixin.qq.com/cgi-bin/component/api_component_token"
	getPreCodeURL           = "https://api.weixin.qq.com/cgi-bin/component/api_create_preauthcode?component_access_token=%s"
	queryAuthURL            = "https://api.weixin.qq.com/cgi-bin/component/api_query_auth?component_access_token=%s"
	refreshTokenURL         = "https://api.weixin.qq.com/cgi-bin/component/api_authorizer_token?component_access_token=%s"
	getComponentInfoURL     = "https://api.weixin.qq.com/cgi-bin/component/api_get_authorizer_info?component_access_token=%s"
	getComponentConfigURL   = "https://api.weixin.qq.com/cgi-bin/component/api_get_authorizer_option?component_access_token=%s"
    getAuthPageURL          = "https://mp.weixin.qq.com/cgi-bin/componentloginpage?component_appid=%s&pre_auth_code=%s&redirect_uri=%s&auth_type=%s"
    getAuthMobileURL        = "https://mp.weixin.qq.com/safe/bindcomponent?action=bindcomponent&no_scan=1&component_appid=%s&pre_auth_code=%s&redirect_uri=%s&auth_type=%s#wechat_redirect"
    modifyDomainURL         = "https://api.weixin.qq.com/wxa/modify_domain?access_token=%s"
    commitURL               = "https://api.weixin.qq.com/wxa/commit?access_token=%s"
    getQrCodeURL            = "https://api.weixin.qq.com/wxa/get_qrcode?access_token=%s&path=%s"
)

// ComponentAccessToken 第三方平台
type ComponentAccessToken struct {
	AccessToken string `json:"component_access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

// GetComponentAccessToken 获取 ComponentAccessToken
func (ctx *Context) GetComponentAccessToken(verifyTicket string) (string, error) {
	accessTokenCacheKey := fmt.Sprintf("component_access_token_%s", ctx.AppID)
	val := ctx.Cache.Get(accessTokenCacheKey)
	if val != nil {
		return val.(string), nil
	}

    cat, err := ctx.SetComponentAccessToken(verifyTicket)
	if err != nil {
		return "", err
	}
	return cat.AccessToken, nil
}

// SetComponentAccessToken 通过component_verify_ticket 获取 ComponentAccessToken
func (ctx *Context) SetComponentAccessToken(verifyTicket string) (*ComponentAccessToken, error) {
	body := map[string]string{
		"component_appid":         ctx.AppID,
		"component_appsecret":     ctx.AppSecret,
		"component_verify_ticket": verifyTicket,
	}
	respBody, err := util.PostJSON(componentAccessTokenURL, body)
	if err != nil {
		return nil, err
	}

	at := &ComponentAccessToken{}
	if err := json.Unmarshal(respBody, at); err != nil {
		return nil, err
	}

	accessTokenCacheKey := fmt.Sprintf("component_access_token_%s", ctx.AppID)
	expires := at.ExpiresIn - 1500
	ctx.Cache.Set(accessTokenCacheKey, at.AccessToken, time.Duration(expires)*time.Second)
	return at, nil
}

// GetPreCode 获取预授权码
func (ctx *Context) GetPreCode() (string, error) {
	preCodeCacheKey := fmt.Sprintf("pre_code_token_%s", ctx.AppID)
	val := ctx.Cache.Get(preCodeCacheKey)
	if val != nil {
		return val.(string), nil
	}

	cat, err := ctx.GetComponentAccessToken("")
	if err != nil {
		return "", err
	}
	req := map[string]string{
		"component_appid": ctx.AppID,
	}
	uri := fmt.Sprintf(getPreCodeURL, cat)
	body, err := util.PostJSON(uri, req)
	if err != nil {
		return "", err
	}

	var ret struct {
		PreCode string `json:"pre_auth_code"`
        ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &ret); err != nil {
		return "", err
	}
	expires := ret.ExpiresIn - 120
	ctx.Cache.Set(preCodeCacheKey, ret.PreCode, time.Duration(expires)*time.Second)

	return ret.PreCode, nil
}

// 获取授权注册页面地址
func (ctx *Context) GetAuthPageUri(redirectUri string, authType string) (string, error) {
	preAuthCode, err := ctx.GetPreCode()
	if err != nil {
		return "", err
	}
	uri := fmt.Sprintf(getAuthPageURL, ctx.AppID, preAuthCode, redirectUri, authType)
	return uri, nil
}

// 获取授权移动端链接地址
func (ctx *Context) GetAuthMobileUri(redirectUri string, authType string) (string, error) {
	preAuthCode, err := ctx.GetPreCode()
	if err != nil {
		return "", err
	}
	uri := fmt.Sprintf(getAuthMobileURL, ctx.AppID, preAuthCode, redirectUri, authType)
	return uri, nil
}

// ID 微信返回接口中各种类型字段
type ID struct {
	ID int `json:"id"`
}

// AuthBaseInfo 授权的基本信息
type AuthBaseInfo struct {
	AuthrAccessToken
	FuncInfo []AuthFuncInfo `json:"func_info"`
}

// AuthFuncInfo 授权的接口内容
type AuthFuncInfo struct {
	FuncscopeCategory ID `json:"funcscope_category"`
}

// AuthrAccessToken 授权方AccessToken
type AuthrAccessToken struct {
	Appid        string `json:"authorizer_appid"`
	AccessToken  string `json:"authorizer_access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"authorizer_refresh_token"`
}

// QueryAuthCode 使用授权码换取公众号或小程序的接口调用凭据和授权信息
func (ctx *Context) QueryAuthCode(authCode string) (*AuthBaseInfo, error) {
	cat, err := ctx.GetComponentAccessToken("")
	if err != nil {
		return nil, err
	}

	req := map[string]string{
		"component_appid":    ctx.AppID,
		"authorization_code": authCode,
	}
	uri := fmt.Sprintf(queryAuthURL, cat)
	body, err := util.PostJSON(uri, req)
	if err != nil {
		return nil, err
	}

	var ret struct {
		Info *AuthBaseInfo `json:"authorization_info"`
	}

	if err := json.Unmarshal(body, &ret); err != nil {
		return nil, err
	}

	refreshTokenCacheKey := fmt.Sprintf("authorizer_refresh_token_%s", ret.Info.AuthrAccessToken.Appid)
	ctx.Cache.Set(refreshTokenCacheKey, ret.Info.AuthrAccessToken.RefreshToken, time.Hour*24)

	authrTokenCacheKey := fmt.Sprintf("authorizer_access_token_%s", ret.Info.AuthrAccessToken.Appid)
	ctx.Cache.Set(authrTokenCacheKey, ret.Info.AuthrAccessToken.AccessToken, time.Minute*80)

	return ret.Info, nil
}

// RefreshAuthrToken 获取（刷新）授权公众号或小程序的接口调用凭据（令牌）
func (ctx *Context) RefreshAuthrToken(appid string) (*AuthrAccessToken, error) {
	refreshTokenCacheKey := fmt.Sprintf("authorizer_refresh_token_%s", appid)
	refreshToken := ctx.Cache.Get(refreshTokenCacheKey)
	if refreshToken == nil {
		return nil, fmt.Errorf("cannot get authorizer %s refresh token", appid)
	}

	cat, err := ctx.GetComponentAccessToken("")
	if err != nil {
		return nil, err
	}

	req := map[string]string{
		"component_appid":          ctx.AppID,
		"authorizer_appid":         appid,
		"authorizer_refresh_token": refreshToken.(string),
	}
	uri := fmt.Sprintf(refreshTokenURL, cat)
	body, err := util.PostJSON(uri, req)
	if err != nil {
		return nil, err
	}

	ret := &AuthrAccessToken{}
	if err := json.Unmarshal(body, ret); err != nil {
		return nil, err
	}

	ctx.Cache.Set(refreshTokenCacheKey, ret.RefreshToken, time.Hour*24)

	authrTokenCacheKey := fmt.Sprintf("authorizer_access_token_%s", appid)
	ctx.Cache.Set(authrTokenCacheKey, ret.AccessToken, time.Minute*80)

	return ret, nil
}

// GetAuthrAccessToken 获取授权方AccessToken
func (ctx *Context) GetAuthrAccessToken(appid string) (string, error) {
	authrTokenKey := "authorizer_access_token_" + appid
	val := ctx.Cache.Get(authrTokenKey)
	if val == nil {
		return "", fmt.Errorf("cannot get authorizer %s access token", appid)
	}
	return val.(string), nil
}

// AuthorizerInfo 授权方详细信息
type AuthorizerInfo struct {
	NickName        string `json:"nick_name"`
	HeadImg         string `json:"head_img"`
	ServiceTypeInfo ID     `json:"service_type_info"`
	VerifyTypeInfo  ID     `json:"verify_type_info"`
	UserName        string `json:"user_name"`
	PrincipalName   string `json:"principal_name"`
	BusinessInfo    struct {
		OpenStore string `json:"open_store"`
		OpenScan  string `json:"open_scan"`
		OpenPay   string `json:"open_pay"`
		OpenCard  string `json:"open_card"`
		OpenShake string `json:"open_shake"`
	}
	Alias     string `json:"alias"`
	QrcodeURL string `json:"qrcode_url"`
}

// GetAuthrInfo 获取授权方的帐号基本信息
func (ctx *Context) GetAuthrInfo(appid string) (*AuthorizerInfo, *AuthBaseInfo, error) {
	cat, err := ctx.GetComponentAccessToken("")
	if err != nil {
		return nil, nil, err
	}

	req := map[string]string{
		"component_appid":  ctx.AppID,
		"authorizer_appid": appid,
	}

	uri := fmt.Sprintf(getComponentInfoURL, cat)
	body, err := util.PostJSON(uri, req)
	if err != nil {
		return nil, nil, err
	}

	var ret struct {
		AuthorizerInfo    *AuthorizerInfo `json:"authorizer_info"`
		AuthorizationInfo *AuthBaseInfo   `json:"authorization_info"`
	}
	if err := json.Unmarshal(body, &ret); err != nil {
		return nil, nil, err
	}

	return ret.AuthorizerInfo, ret.AuthorizationInfo, nil
}

// ServerDomain 服务器域名
type ServerDomain struct {
	ErrCode         int64  `json:"errcode"`
	ErrMsg          string `json:"errmsg"`
	RequestDomain   []string `json:"requestdomain"`
	WsrequestDomain []string `json:"wsrequestdomain"`
	UploadDomain    []string `json:"uploaddomain"`
	DownloadDomain  []string `json:"downloaddomain"`
}
// 设置小程序服务器域名
func (ctx *Context) ModifyDomain(appid string, req map[string]string) (*ServerDomain, error) {
    at, err := ctx.GetAuthrAccessToken(appid)
    if err != nil {
		return nil, err
    }
    uri := fmt.Sprintf(modifyDomainURL, at)
    body, err := util.PostJSON(uri, req)
    if err != nil {
		return nil, err
    }
    var ret ServerDomain
	if err := json.Unmarshal(body, &ret); err != nil {
		return nil, err
	}
	if ret.ErrCode != 0 {
		return nil, fmt.Errorf("%s Error , errcode=%d , errmsg=%s", "ModifyDomain", ret.ErrCode, ret.ErrMsg)
	}
    return &ret, nil
}

// 为授权的小程序帐号上传小程序代码
func (ctx *Context) Commit(appid string, req map[string]string) (error) {
    at, err := ctx.GetAuthrAccessToken(appid)
    if err != nil {
		return err
    }
    uri := fmt.Sprintf(commitURL, at)
    body, err := util.PostJSON(uri, req)
    if err != nil {
		return err
    }
    if err := util.DecodeWithCommonError(body, "Commit"); err != nil {
        return err
    }
    return nil
}

// 获取体验小程序的体验二维码
func (ctx *Context) GetQrCode(appid string, page string) ([]byte, error) {
    at, err := ctx.GetAuthrAccessToken(appid)
    if err != nil {
		return nil, err
    }
    uri := fmt.Sprintf(getQrCodeURL, at, page)
    body, err := util.HTTPGet(uri)
    if err != nil {
        return nil, err
    }
    return body, nil
}
