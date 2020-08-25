package context

import (
	"encoding/json"
	"fmt"
	"time"
    "errors"

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
    getTemplateListURL      = "https://api.weixin.qq.com/wxa/gettemplatelist?access_token=%s"
    fastRegisterWeappURL    = "https://api.weixin.qq.com/cgi-bin/component/fastregisterweapp?action=%s&component_access_token=%s"
    // 以下access_token 为 AuthrAccessToken
    modifyDomainURL         = "https://api.weixin.qq.com/wxa/modify_domain?access_token=%s"
    commitURL               = "https://api.weixin.qq.com/wxa/commit?access_token=%s"
    getQrCodeURL            = "https://api.weixin.qq.com/wxa/get_qrcode?access_token=%s&path=%s"
    submitAuditURL          = "https://api.weixin.qq.com/wxa/submit_audit?access_token=%s"
    getAuditStatusURL       = "https://api.weixin.qq.com/wxa/get_auditstatus?access_token=%s"
    getLatestAuditStatusURL = "https://api.weixin.qq.com/wxa/get_latest_auditstatus?access_token=%s"
    releaseURL              = "https://api.weixin.qq.com/wxa/release?access_token=%s"
    changeVisitStatusURL    = "https://api.weixin.qq.com/wxa/change_visitstatus?access_token=%s"
    revertCodeReleaseURL    = "https://api.weixin.qq.com/wxa/revertcoderelease?access_token=%s"
    setSupportVersionURL    = "https://api.weixin.qq.com/cgi-bin/wxopen/setweappsupportversion?access_token=%s"
)

// ComponentAccessToken 第三方平台
type ComponentAccessToken struct {
	AccessToken string `json:"component_access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

// AuditStatus 审核状态结果
type AuditStatus struct {
    Finish bool
    Pass bool
    Message string
    AuditId int64
    ScreenShot string
}

// GetComponentAccessToken 获取 ComponentAccessToken
func (ctx *Context) GetComponentAccessToken(verifyTicket string) (string, error) {
    if "" != verifyTicket {
        // 更新缓存中的 verifyTicket
        verifyTicketCacheKey := fmt.Sprintf("component_verify_ticket_%s", ctx.AppID)
        ctx.Cache.Set(verifyTicketCacheKey, verifyTicket, time.Minute*60)
    }

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
    var ok bool
    if "" == verifyTicket {
        // 用缓存中的 verifyTicket 获取 AccessToken
        verifyTicketCacheKey := fmt.Sprintf("component_verify_ticket_%s", ctx.AppID)
        verifyTicket, ok = ctx.Cache.Get(verifyTicketCacheKey).(string)
        if !ok {
            return nil, errors.New("Ticket is empty, please check service status.")
        }
    }
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
func (ctx *Context) GetPreCode(token string) (string, error) {
    preCodeCacheKey := fmt.Sprintf("pre_code_token_%s", ctx.AppID)
    val := ctx.Cache.Get(preCodeCacheKey)
    if val != nil {
        return val.(string), nil
    }

    var cat string
    var err error
    if token == "" {
        cat, err = ctx.GetComponentAccessToken("")
        if err != nil {
            return "", err
        }
    } else {
        cat = token
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

// 清除预授权码
func (ctx *Context) ClearPreCode() error {
	preCodeCacheKey := fmt.Sprintf("pre_code_token_%s", ctx.AppID)
	return ctx.Cache.Delete(preCodeCacheKey)
}

// 获取授权注册页面地址
func (ctx *Context) GetAuthPageUri(token string, redirectUri string, authType string) (string, error) {
	preAuthCode, err := ctx.GetPreCode(token)
	if err != nil {
		return "", err
	}
	uri := fmt.Sprintf(getAuthPageURL, ctx.AppID, preAuthCode, redirectUri, authType)
	return uri, nil
}

// 获取授权移动端链接地址
func (ctx *Context) GetAuthMobileUri(token string, redirectUri string, authType string) (string, error) {
	preAuthCode, err := ctx.GetPreCode(token)
	if err != nil {
		return "", err
	}
	uri := fmt.Sprintf(getAuthMobileURL, ctx.AppID, preAuthCode, redirectUri, authType)
	return uri, nil
}

// ID 微信返回接口中各种类型字段
type ID struct {
	ID int64 `json:"id"`
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

// QueryAuthCode 使用授权码换取公众号或小程序的接口调用凭据和授权信息, 并清除预授权码
func (ctx *Context) QueryAuthCode(token, authCode string) (*AuthBaseInfo, error) {
    ctx.ClearPreCode() // 清除预授权码

    var cat string
    var err error
    if token == "" {
        cat, err = ctx.GetComponentAccessToken("")
        if err != nil {
            return nil, err
        }
    } else {
        cat = token
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
	if val != nil {
		return val.(string), nil
	}
    at, err := ctx.RefreshAuthrToken(appid)
	if err != nil {
		return "", err
	}

	return at.AccessToken, nil
}

// AuthorizerInfo 授权方详细信息
type mpInfo struct {
    Network interface{} `json:"network"`
    Categories interface{} `json:"categories"`
    VisitStatus int64 `json:"visit_status"`
}
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
	Miniprograminfo mpInfo `json:"miniprograminfo"`
}

// GetAuthrInfo 获取授权方的帐号基本信息
func (ctx *Context) GetAuthrInfo(token, appid string) (*AuthorizerInfo, *AuthBaseInfo, error) {
    var cat string
    var err error
    if token == "" {
        cat, err = ctx.GetComponentAccessToken("")
        if err != nil {
            return nil, nil, err
        }
    } else {
        cat = token
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

// 获取代码模板列表
type Template struct {
	CreateTime  int64 `json:"create_time"`
	UserVersion string `json:"user_version"`
	UserDesc    string `json:"user_desc"`
	TemplateId  int64 `json:"template_id"`
}
type TemplateList struct {
	ErrCode      int64  `json:"errcode"`
	ErrMsg       string `json:"errmsg"`
    TemplateList []Template `json:"template_list"`
}
func (ctx *Context) GetTemplateList(token string) ([]Template, error) {
    var cat string
    var err error
    var ret TemplateList
    if token == "" {
        cat, err = ctx.GetComponentAccessToken("")
        if err != nil {
            return nil, err
        }
    } else {
        cat = token
    }
    uri := fmt.Sprintf(getTemplateListURL, cat)
    body, err := util.HTTPGet(uri)
    if err != nil {
        return nil, err
    }
	if err = json.Unmarshal(body, &ret); err != nil {
        return nil, err
	}
	if ret.ErrCode != 0 {
        err = errors.New(ret.ErrMsg)
		return nil, err
	}
    return ret.TemplateList, nil
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
func (ctx *Context) ModifyDomain(token, appid string, req map[string]interface{}) (*ServerDomain, error) {
    var at string
    var err error
    if token == "" {
        at, err = ctx.GetAuthrAccessToken(appid)
        if err != nil {
            return nil, err
        }
    } else {
        at = token
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
func (ctx *Context) Commit(token, appid string, req map[string]string) (error) {
    var at string
    var err error
    if token == "" {
        at, err = ctx.GetAuthrAccessToken(appid)
        if err != nil {
            return err
        }
    } else {
        at = token
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
func (ctx *Context) GetQrCode(token, appid string, page string) ([]byte, error) {
    var at string
    var err error
    if token == "" {
        at, err = ctx.GetAuthrAccessToken(appid)
        if err != nil {
            return nil, err
        }
    } else {
        at = token
    }
    uri := fmt.Sprintf(getQrCodeURL, at, page)
    body, err := util.HTTPGet(uri)
    if err != nil {
        return nil, err
    }
    return body, nil
}

// 为授权的小程序上传的代码 提交审核
func (ctx *Context) SubmitAudit(token, appid string, req map[string]string) (int64, error) {
    var at string
    var err error
    if token == "" {
        at, err = ctx.GetAuthrAccessToken(appid)
        if err != nil {
            return 0, err
        }
    } else {
        at = token
    }
    uri := fmt.Sprintf(submitAuditURL, at)
    body, err := util.PostJSON(uri, req)
    if err != nil {
		return 0, err
    }
    fmt.Println("body:", string(body))

	var ret struct {
        ErrCode int64  `json:"errcode"`
        ErrMsg  string `json:"errmsg"`
		Auditid int64  `json:"auditid"`
	}
	if err := json.Unmarshal(body, &ret); err != nil {
		return 0, err
	}
	if ret.ErrCode != 0 {
        return 0, errors.New(ret.ErrMsg)
	}

    return ret.Auditid, nil
}

// 查询审核状态
func (ctx *Context) GetAuditStatus(token, appid string, auditid int64) (status AuditStatus, err error) {
    var at string
    var body []byte
    if token == "" {
        at, err = ctx.GetAuthrAccessToken(appid)
        if err != nil {
            return
        }
    } else {
        at = token
    }
    if auditid == 0 {
        // 查询最新一次提交的审核状态
        uri := fmt.Sprintf(getLatestAuditStatusURL, at)
        body, err = util.HTTPGet(uri)
    } else {
        // 查询指定发布审核单的审核状态
        uri := fmt.Sprintf(getAuditStatusURL, at)
        req := map[string]int64{
            "auditid": auditid,
        }
        body, err = util.PostJSON(uri, req)
    }
    if err != nil {
        return
    }
    fmt.Println("body:", string(body))

	var ret struct {
        ErrCode    int64  `json:"errcode"`
        ErrMsg     string `json:"errmsg"`
		Auditid    int64  `json:"auditid"`
        Status     int64  `json:"status"`
        Reason     string `json:"reason"`
		ScreenShot string `json:"screenshot"`
	}
	if err = json.Unmarshal(body, &ret); err != nil {
		return
	}
	if ret.ErrCode != 0 {
        err = errors.New(ret.ErrMsg)
		return
	}

    if ret.Auditid != 0 {
        status.AuditId = ret.Auditid // 查询最新一次提交的审核状态, 会返回对应的 Auditid
    } else {
        status.AuditId = auditid
    }
    status.ScreenShot = ret.ScreenShot

    switch ret.Status {
    case 0:
        status.Finish = true
        status.Pass = true
    case 1:
        status.Finish = true
        status.Message = "审核被拒绝，拒绝原因："+ret.Reason
    case 2:
        status.Message = "审核中"
    case 3:
        status.Finish = true
        status.Message = "已撤回"
    case 4:
        status.Message = "审核延后，延后原因："+ret.Reason
    }
    return
}

// 发布最后一个审核通过的小程序代码版本
func (ctx *Context) Release(token, appid string, req map[string]string) (error) {
    var at string
    var err error
    if token == "" {
        at, err = ctx.GetAuthrAccessToken(appid)
        if err != nil {
            return err
        }
    } else {
        at = token
    }
    uri := fmt.Sprintf(releaseURL, at)
    body, err := util.PostJSON(uri, req)
    if err != nil {
		return err
    }
    if err := util.DecodeWithCommonError(body, "Release"); err != nil {
        return err
    }
    return nil
}

// 修改小程序线上代码的可见状态
func (ctx *Context) ChangeVisitStatus(token, appid string, req map[string]string) (error) {
    var at string
    var err error
    if token == "" {
        at, err = ctx.GetAuthrAccessToken(appid)
        if err != nil {
            return err
        }
    } else {
        at = token
    }
    uri := fmt.Sprintf(changeVisitStatusURL, at)
    body, err := util.PostJSON(uri, req)
    if err != nil {
		return err
    }
    if err := util.DecodeWithCommonError(body, "ChangeVisitStatus"); err != nil {
        return err
    }
    return nil
}

// 将小程序的线上版本进行回退
func (ctx *Context) RevertCodeRelease(token, appid string) (error) {
    var at string
    var err error
    if token == "" {
        at, err = ctx.GetAuthrAccessToken(appid)
        if err != nil {
            return err
        }
    } else {
        at = token
    }
    uri := fmt.Sprintf(revertCodeReleaseURL, at)
    body, err := util.HTTPGet(uri)
    if err != nil {
		return err
    }
    if err := util.DecodeWithCommonError(body, "RevertCodeRelease"); err != nil {
        return err
    }
    return nil
}

// 设置最低基础库版本
func (ctx *Context) SetSupportVersion(token, appid string, req map[string]string) (error) {
    var at string
    var err error
    if token == "" {
        at, err = ctx.GetAuthrAccessToken(appid)
        if err != nil {
            return err
        }
    } else {
        at = token
    }
    uri := fmt.Sprintf(setSupportVersionURL, at)
    body, err := util.PostJSON(uri, req)
    if err != nil {
		return err
    }
    if err := util.DecodeWithCommonError(body, "setSupportVersion"); err != nil {
        return err
    }
    return nil
}

// 快速创建小程序
func (ctx *Context) FastRegisterWeapp(token string, action string, req map[string]string) (isFinish bool, err error) {
    var cat string
    if token == "" {
        cat, err = ctx.GetComponentAccessToken("")
        if err != nil {
            return
        }
    } else {
        cat = token
    }

    uri := fmt.Sprintf(fastRegisterWeappURL, action, cat)
    var body []byte
    body, err = util.PostJSON(uri, req)
    if err != nil {
        return
    }
    fmt.Println("body:", string(body))

	var ret struct {
        ErrCode    int64  `json:"errcode"`
        ErrMsg     string `json:"errmsg"`
	}
	if err = json.Unmarshal(body, &ret); err != nil {
		return
	}

    switch ret.ErrCode {
    case 0:
        isFinish = true
    case -1:
        isFinish = true
        err = errors.New("非法 action 参数")
    case 61070:
        isFinish = true
        err = errors.New("法人姓名与微信号不一致")
    case 86004:
        isFinish = true
        err = errors.New("无效微信号")
    case 89247:
        isFinish = true
        err = errors.New("内部错误")
    case 89248:
        isFinish = true
        err = errors.New("企业代码类型无效，请选择正确类型填写")
    case 89249:
        isFinish = true
        err = errors.New("该主体已有任务执行中，距上次任务 24h 后再试")
    case 89250:
        err = errors.New("未找到该任务")
    case 89251:
        err = errors.New("待法人人脸核身校验")
    case 89252:
        err = errors.New("法人&企业信息一致性校验中")
    case 89253:
        isFinish = true
        err = errors.New("缺少参数")
    case 89254:
        isFinish = true
        err = errors.New("第三方权限集不全，补全权限集全网发布后生效")
    default:
        err = errors.New(ret.ErrMsg)
    }

    return
}
