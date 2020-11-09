package pay

import (
	"bytes"
	"encoding/xml"
	"errors"
	"sort"
	"strconv"
    "time"
    "log"

	"github.com/silenceper/wechat/context"
	"github.com/silenceper/wechat/util"
)

var payGateway = "https://api.mch.weixin.qq.com/pay/unifiedorder"
var payQueryURL = "https://api.mch.weixin.qq.com/pay/orderquery"

// Pay struct extends context
type Pay struct {
	*context.Context
}

// Params was NEEDED when request unifiedorder
// 传入的参数，用于生成 prepay_id 的必需参数
type Params struct {
	TotalFee   string
	CreateIP   string
	Body       string
	OutTradeNo string
	OpenID     string
	TradeType  string
    ProductID  string
	Attach     string
}

// Config 是传出用于 jsdk 用的参数
type Config struct {
	Timestamp int64
	NonceStr  string
	PrePayID  string
	SignType  string
	Sign      string
}

// PreOrder 是 unifie order 接口的返回
type PreOrder struct {
	ReturnCode string `xml:"return_code"`
	ReturnMsg  string `xml:"return_msg"`
	AppID      string `xml:"appid,omitempty"`
	MchID      string `xml:"mch_id,omitempty"`
	NonceStr   string `xml:"nonce_str,omitempty"`
	Sign       string `xml:"sign,omitempty"`
	ResultCode string `xml:"result_code,omitempty"`
	TradeType  string `xml:"trade_type,omitempty"`
	PrePayID   string `xml:"prepay_id,omitempty"`
	CodeURL    string `xml:"code_url,omitempty"`
	ErrCode    string `xml:"err_code,omitempty"`
	ErrCodeDes string `xml:"err_code_des,omitempty"`
}

// WxaPayRequest 是 WxaPay 接口的返回，是微信小程序调起支付所需的 接口请求参数
type WxaPayRequest struct {
	Timestamp string
	NonceStr  string
	Package   string
	SignType  string
	PaySign   string
}

//payRequest 接口请求参数
type payRequest struct {
	AppID          string `xml:"appid"`
	MchID          string `xml:"mch_id"`
	DeviceInfo     string `xml:"device_info,omitempty"`
	NonceStr       string `xml:"nonce_str"`
	Sign           string `xml:"sign"`
	SignType       string `xml:"sign_type,omitempty"`
	Body           string `xml:"body"`
	Detail         string `xml:"detail,omitempty"`
	Attach         string `xml:"attach,omitempty"`      //附加数据
	OutTradeNo     string `xml:"out_trade_no"`          //商户订单号
	FeeType        string `xml:"fee_type,omitempty"`    //标价币种
	TotalFee       string `xml:"total_fee"`             //标价金额
	SpbillCreateIP string `xml:"spbill_create_ip"`      //终端IP
	TimeStart      string `xml:"time_start,omitempty"`  //交易起始时间
	TimeExpire     string `xml:"time_expire,omitempty"` //交易结束时间
	GoodsTag       string `xml:"goods_tag,omitempty"`   //订单优惠标记
	NotifyURL      string `xml:"notify_url"`            //通知地址
	TradeType      string `xml:"trade_type"`            //交易类型
	ProductID      string `xml:"product_id,omitempty"`  //商品ID
	LimitPay       string `xml:"limit_pay,omitempty"`   //
	OpenID         string `xml:"openid,omitempty"`      //用户标识
	SceneInfo      string `xml:"scene_info,omitempty"`  //场景信息
}

// payQuery 接口请求参数
type queryRequest struct {
	AppID          string `xml:"appid"`
	MchID          string `xml:"mch_id"`
	OutTradeNo     string `xml:"out_trade_no"`          //商户订单号
	NonceStr       string `xml:"nonce_str"`
	Sign           string `xml:"sign"`
	SignType       string `xml:"sign_type,omitempty"`
}

// QueryResult 是 payQuery 接口的返回
type QueryResult struct {
	ReturnCode     string `xml:"return_code"`      // 返回状态码: SUCCESS/FAIL
	ReturnMsg      string `xml:"return_msg"`       // 返回信息，如非空，为错误原因
	Appid          string `xml:"appid"`            // 小程序ID
	MchId          string `xml:"mch_id"`           // 商户号
	NonceStr       string `xml:"nonce_str"`        // 随机字符串
	Sign           string `xml:"sign"`             // 签名
	ResultCode     string `xml:"result_code"`      // 业务结果: SUCCESS/FAIL
	ErrCode        string `xml:"err_code"`         // 错误代码
	ErrCodeDes     string `xml:"err_code_des"`     // 错误代码描述
	Openid         string `xml:"openid"`           // 用户标识
	IsSubscribe    string `xml:"is_subscribe"`     // 是否关注公众账号
	TradeType      string `xml:"trade_type"`       // 交易类型
    TradeState     string `xml:"trade_state"`      // 交易状态: SUCCESS—支付成功 REFUND—转入退款 NOTPAY—未支付 CLOSED—已关闭 REVOKED—已撤销（刷卡支付） USERPAYING--用户支付中 PAYERROR--支付失败(其他原因，如银行返回失败)
	BankType       string `json:"bank_type"`       // 付款银行
	TotalFee       string `xml:"total_fee"`        // 订单金额
	FeeType        string `xml:"fee_type"`         // 货币种类
	CashFee        string `json:"cash_fee"`        // 现金支付金额
	TransactionId  string `xml:"transaction_id"`   // 微信支付订单号
	OutTradeNo     string `xml:"out_trade_no"`     // 商户订单号
	Attach         string `xml:"attach"`           // 商家数据包: 统一下单时提交 uid:oid
	TimeEnd        string `xml:"time_end"`         // 支付完成时间
	TradeStateDesc string `xml:"trade_state_desc"` // 交易状态描述
}

// NewPay return an instance of Pay package
func NewPay(ctx *context.Context) *Pay {
	pay := Pay{Context: ctx}
	return &pay
}

// Sign return str and sign for param
func (pcf *Pay) Sign(param interface{}) (str, sign string) {
	bizKey := "&key=" + pcf.PayKey
	str = orderParam(param, bizKey)
	sign = util.MD5Sum(str)
    return
}

// PrePayOrder return data for invoke wechat payment
func (pcf *Pay) PrePayOrder(p *Params) (payOrder PreOrder, err error) {
	nonceStr := util.RandomStr(32)
	param := make(map[string]interface{})
	param["appid"] = pcf.AppID
	param["body"] = p.Body
	param["mch_id"] = pcf.PayMchID
	param["nonce_str"] = nonceStr
	param["notify_url"] = pcf.PayNotifyURL
	param["out_trade_no"] = p.OutTradeNo
	param["spbill_create_ip"] = p.CreateIP
	param["total_fee"] = p.TotalFee
	param["trade_type"] = p.TradeType
	param["product_id"] = p.ProductID
	param["openid"] = p.OpenID
	param["attach"] = p.Attach

    str, sign := pcf.Sign(param)
    log.Println("PrePayOrder")
    log.Println(str, sign)
	request := payRequest{
		AppID:          pcf.AppID,
		MchID:          pcf.PayMchID,
		NonceStr:       nonceStr,
		Sign:           sign,
		Body:           p.Body,
		OutTradeNo:     p.OutTradeNo,
		TotalFee:       p.TotalFee,
		SpbillCreateIP: p.CreateIP,
		NotifyURL:      pcf.PayNotifyURL,
		TradeType:      p.TradeType,
		ProductID:      p.ProductID,
		OpenID:         p.OpenID,
		Attach:         p.Attach,
	}
	rawRet, err := util.PostXML(payGateway, request)
	if err != nil {
		return
	}
	err = xml.Unmarshal(rawRet, &payOrder)
	if err != nil {
		return
	}
	if payOrder.ReturnCode == "SUCCESS" {
		//pay success
		if payOrder.ResultCode == "SUCCESS" {
			err = nil
			return
		}
		err = errors.New(payOrder.ErrCode + payOrder.ErrCodeDes)
		return
	}
	err = errors.New("[msg : xmlUnmarshalError] [rawReturn : " + string(rawRet) + "] [params : " + str + "] [sign : " + sign + "]")
	return
}

// CodeURL will request wechat merchant api and request for a pre payment order codeURL
func (pcf *Pay) CodeURL(p *Params) (codeURL string, err error) {
	order, err := pcf.PrePayOrder(p)
	if err != nil {
		return
	}
	if order.CodeURL == "" {
		err = errors.New("empty codeURL")
	}
	codeURL = order.CodeURL
	return
}

// PrePayID will request wechat merchant api and request for a pre payment order id
func (pcf *Pay) PrePayID(p *Params) (prePayID string, err error) {
	order, err := pcf.PrePayOrder(p)
	if err != nil {
		return
	}
	if order.PrePayID == "" {
		err = errors.New("empty prepayid")
	}
	prePayID = order.PrePayID
	return
}

// WxaPay will return wxa pay request
func (pcf *Pay) WxaPay(p *Params) (request WxaPayRequest, err error) {
	prePayID, err := pcf.PrePayID(p)
	if err != nil {
		return
	}
	nonceStr := util.RandomStr(32)
	param := make(map[string]string)
	param["appId"] = pcf.AppID
	param["nonceStr"] = nonceStr
	param["package"] = "prepay_id=" + prePayID
	param["signType"] = "MD5"
	param["timeStamp"] = strconv.FormatInt(time.Time.Unix(time.Now()), 10)
	str, sign := pcf.Sign(param)
    log.Println(str, sign)
    request = WxaPayRequest{ 
        Timestamp: param["timeStamp"],
        NonceStr:  param["nonceStr"],
        Package:   param["package"],
        SignType:  param["signType"],
        PaySign:   sign,
    }
	return
}

// PayQuery return queryResult
func (pcf *Pay) PayQuery(p *Params) (queryResult QueryResult, xmlBody []byte, err error) {
	nonceStr := util.RandomStr(32)
	param := make(map[string]interface{})
	param["appid"] = pcf.AppID
	param["mch_id"] = pcf.PayMchID
	param["out_trade_no"] = p.OutTradeNo
	param["nonce_str"] = nonceStr

    str, sign := pcf.Sign(param)
    log.Println("PayQuery")
    log.Println(str, sign)
	request := queryRequest{
		AppID:          pcf.AppID,
		MchID:          pcf.PayMchID,
		OutTradeNo:     p.OutTradeNo,
		NonceStr:       nonceStr,
		Sign:           sign,
	}
	xmlBody, err = util.PostXML(payQueryURL, request)
	if err != nil {
		return
	}
	err = xml.Unmarshal(xmlBody, &queryResult)
	if err != nil {
		return
	}
	if queryResult.ReturnCode == "SUCCESS" {
		//query success
		if queryResult.ResultCode == "SUCCESS" {
			err = nil
			return
		}
		err = errors.New(queryResult.ErrCode + queryResult.ErrCodeDes)
		return
	}
	err = errors.New("[msg : xmlUnmarshalError] [rawReturn : " + string(xmlBody) + "] [params : " + str + "] [sign : " + sign + "]")
	return
}

// order params
func orderParam(source interface{}, bizKey string) (returnStr string) {
	switch v := source.(type) {
	case map[string]string:
		keys := make([]string, 0, len(v))
		for k := range v {
			if k == "sign" {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var buf bytes.Buffer
		for _, k := range keys {
			if v[k] == "" {
				continue
			}
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(k)
			buf.WriteByte('=')
			buf.WriteString(v[k])
		}
		buf.WriteString(bizKey)
		returnStr = buf.String()
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for k := range v {
			if k == "sign" {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var buf bytes.Buffer
		for _, k := range keys {
			if v[k] == "" {
				continue
			}
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(k)
			buf.WriteByte('=')
			switch vv := v[k].(type) {
			case string:
				buf.WriteString(vv)
			case int:
				buf.WriteString(strconv.FormatInt(int64(vv), 10))
			default:
				panic("params type not supported")
			}
		}
		buf.WriteString(bizKey)
		returnStr = buf.String()
	}
	return
}
