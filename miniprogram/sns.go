package miniprogram

import (
	"fmt"
    "time"
	"encoding/json"
    "encoding/hex"
    "crypto/sha256"

	"github.com/silenceper/wechat/util"
)

const (
	code2SessionURL = "https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code"
    trdLoginUrl     = "https://api.weixin.qq.com/sns/component/jscode2session?appid=%s&js_code=%s&grant_type=authorization_code&component_appid=%s&component_access_token=%s"
)

// ResCode2Session 登录凭证校验的返回结果
type ResCode2Session struct {
	util.CommonError

	OpenID     string `json:"openid"`      // 用户唯一标识
	SessionKey string `json:"session_key"` // 会话密钥
	UnionID    string `json:"unionid"`     // 用户在开放平台的唯一标识符，在满足UnionID下发条件的情况下会返回
    Hash       string
}

// Code2Session 登录凭证校验
func (wxa *MiniProgram) Code2Session(jsCode string, hashSalt string) (*ResCode2Session, error) {
	uri := fmt.Sprintf(code2SessionURL, wxa.AppID, wxa.AppSecret, jsCode)
    response, err := util.HTTPGet(uri)
	if err != nil {
		return nil, err
	}
    var result ResCode2Session
	err = json.Unmarshal(response, &result)
	if err != nil {
		return nil, err
	}
	if result.ErrCode != 0 {
		err = fmt.Errorf("Code2Session error : errcode=%v , errmsg=%v", result.ErrCode, result.ErrMsg)
		return nil, err
	}

    hash := sha256.New()
    hash.Write([]byte(result.OpenID + hashSalt))
    str := hex.EncodeToString(hash.Sum(nil))
    sessionKeyCacheKey := fmt.Sprintf("session_key_%s", str)
    wxa.Context.Cache.Set(sessionKeyCacheKey, result.SessionKey, time.Hour*24)
    result.Hash = str
	return &result, nil
}

// 第三方平台代小程序登录
func (wxa *MiniProgram) TrdLogin(jsCode string, ComponentAppid string, ComponentAccessToken string, hashSalt string) (*ResCode2Session, error) {
	uri := fmt.Sprintf(trdLoginUrl, wxa.AppID, jsCode, ComponentAppid, ComponentAccessToken)
    response, err := util.HTTPGet(uri)
    if err != nil {
		return nil, err
	}
    var result ResCode2Session
	err = json.Unmarshal(response, &result)
	if err != nil {
		return nil, err
	}
	if result.ErrCode != 0 {
		err = fmt.Errorf("Code2Session error : errcode=%v , errmsg=%v", result.ErrCode, result.ErrMsg)
		return nil, err
	}

    hash := sha256.New()
    hash.Write([]byte(result.OpenID + hashSalt))
    str := hex.EncodeToString(hash.Sum(nil))
    sessionKeyCacheKey := fmt.Sprintf("session_key_%s", str)
    wxa.Context.Cache.Set(sessionKeyCacheKey, result.SessionKey, time.Hour*24)
    result.Hash = str
    return &result, nil
}

func (wxa *MiniProgram) GetSessionKey(hash string) (string, error) {
    sessionKeyCacheKey := fmt.Sprintf("session_key_%s", hash)
    val := wxa.Context.Cache.Get(sessionKeyCacheKey)
	if val == nil {
        return "", fmt.Errorf("cannot get hash: %s session key", hash)
	}
    return val.(string), nil
}
