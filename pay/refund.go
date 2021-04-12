package pay

import (
	"encoding/xml"
	"errors"
	"fmt"
	"log"

	"github.com/silenceper/wechat/util"
)

var refundGateway = "https://api.mch.weixin.qq.com/secapi/pay/refund"
var refundQueryURL = "https://api.mch.weixin.qq.com/pay/refundquery"

//RefundParams 调用参数
type RefundParams struct {
	TransactionID string
	OutRefundNo   string
	TotalFee      string
	RefundFee     string
	RefundDesc    string
}

//refundRequest 接口请求参数
type refundRequest struct {
	AppID         string `xml:"appid"`
	MchID         string `xml:"mch_id"`
	NonceStr      string `xml:"nonce_str"`
	Sign          string `xml:"sign"`
	SignType      string `xml:"sign_type,omitempty"`
	TransactionID string `xml:"transaction_id"`
	OutRefundNo   string `xml:"out_refund_no"`
	TotalFee      string `xml:"total_fee"`
	RefundFee     string `xml:"refund_fee"`
	RefundDesc    string `xml:"refund_desc,omitempty"`
	NotifyURL     string `xml:"notify_url,omitempty"`
}

//RefundResponse 接口返回
type RefundResponse struct {
	ReturnCode          string `xml:"return_code"`
	ReturnMsg           string `xml:"return_msg"`
	AppID               string `xml:"appid,omitempty"`
	MchID               string `xml:"mch_id,omitempty"`
	NonceStr            string `xml:"nonce_str,omitempty"`
	Sign                string `xml:"sign,omitempty"`
	ResultCode          string `xml:"result_code,omitempty"`
	ErrCode             string `xml:"err_code,omitempty"`
	ErrCodeDes          string `xml:"err_code_des,omitempty"`
	TransactionID       string `xml:"transaction_id,omitempty"`
	OutTradeNo          string `xml:"out_trade_no,omitempty"`
	OutRefundNo         string `xml:"out_refund_no,omitempty"`
	RefundID            string `xml:"refund_id,omitempty"`
	RefundFee           string `xml:"refund_fee,omitempty"`
	SettlementRefundFee string `xml:"settlement_refund_fee,omitempty"`
	TotalFee            string `xml:"total_fee,omitempty"`
	SettlementTotalFee  string `xml:"settlement_total_fee,omitempty"`
	FeeType             string `xml:"fee_type,omitempty"`
	CashFee             string `xml:"cash_fee,omitempty"`
	CashFeeType         string `xml:"cash_fee_type,omitempty"`
}

// refundQuery 接口请求参数
type refundQueryRequest struct {
	AppID       string `xml:"appid"`
	MchID       string `xml:"mch_id"`
	OutRefundNo string `xml:"out_refund_no"` //商户退款单号
	NonceStr    string `xml:"nonce_str"`
	Sign        string `xml:"sign"`
	SignType    string `xml:"sign_type,omitempty"`
}

// RefundQueryResult 是 refundQuery 接口的返回
type RefundQueryResult struct {
	ReturnCode        string `xml:"return_code"`           // 返回状态码: SUCCESS/FAIL
	ReturnMsg         string `xml:"return_msg"`            // 返回信息，如非空，为错误原因
	ResultCode        string `xml:"result_code"`           // 业务结果: SUCCESS/FAIL
	ErrCode           string `xml:"err_code"`              // 错误代码
	ErrCodeDes        string `xml:"err_code_des"`          // 错误代码描述
	Appid             string `xml:"appid"`                 // 小程序ID
	MchId             string `xml:"mch_id"`                // 商户号
	NonceStr          string `xml:"nonce_str"`             // 随机字符串
	Sign              string `xml:"sign"`                  // 签名
	TotalRefundCount  string `xml:"total_refund_count"`    // 订单总退款次数
	TransactionId     string `xml:"transaction_id"`        // 微信支付订单号
	OutTradeNo        string `xml:"out_trade_no"`          // 商户订单号
	TotalFee          string `xml:"total_fee"`             // 订单金额
	FeeType           string `xml:"fee_type"`              // 货币种类
	CashFee           string `xml:"cash_fee"`             // 现金支付金额
	RefundCount       string `xml:"refund_count"`          // 退款笔数
	OutRefundNo       string `xml:"out_refund_no_0"`       // 商户退款单号
	RefundId          string `xml:"refund_id_0"`           // 微信退款单号
	RefundFee         string `xml:"refund_fee_0"`         // 申请退款金额
	RefundStatus      string `xml:"refund_status_0"`       // 退款状态 SUCCESS—退款成功 REFUNDCLOSE—退款关闭 PROCESSING—退款处理中 CHANGE—退款异常，退款到银行发现用户的卡作废或者冻结了，导致原路退款银行卡失败，可前往商户平台（pay.weixin.qq.com）-交易中心，手动处理此笔退款
	RefundRecvAccout_ string `xml:"refund_recv_accout_0"`  // 退款入账账户
	RefundSuccessTime string `xml:"refund_success_time_0"` // 退款成功时间
}

//Refund 退款申请
func (pcf *Pay) Refund(p *RefundParams) (rsp RefundResponse, err error) {
	nonceStr := util.RandomStr(32)
	param := make(map[string]interface{})
	param["appid"] = pcf.AppID
	param["mch_id"] = pcf.PayMchID
	param["nonce_str"] = nonceStr
	param["notify_url"] = pcf.RefundNotifyURL
	param["out_refund_no"] = p.OutRefundNo
	param["refund_desc"] = p.RefundDesc
	param["refund_fee"] = p.RefundFee
	param["total_fee"] = p.TotalFee
	param["sign_type"] = "MD5"
	param["transaction_id"] = p.TransactionID

	bizKey := "&key=" + pcf.PayKey
	str := orderParam(param, bizKey)
	sign := util.MD5Sum(str)
	request := refundRequest{
		AppID:         pcf.AppID,
		MchID:         pcf.PayMchID,
		NonceStr:      nonceStr,
		Sign:          sign,
		SignType:      "MD5",
		TransactionID: p.TransactionID,
		OutRefundNo:   p.OutRefundNo,
		TotalFee:      p.TotalFee,
		RefundFee:     p.RefundFee,
		RefundDesc:    p.RefundDesc,
		NotifyURL:     pcf.RefundNotifyURL,
	}
	rawRet, err := util.PostXMLWithCa(refundGateway, request, pcf.PayCa, pcf.PayMchID)
	if err != nil {
		return
	}
	err = xml.Unmarshal(rawRet, &rsp)
	if err != nil {
		return
	}
	if rsp.ReturnCode == "SUCCESS" {
		if rsp.ResultCode == "SUCCESS" {
			err = nil
			return
		}
		err = fmt.Errorf("refund error, errcode=%s,errmsg=%s", rsp.ErrCode, rsp.ErrCodeDes)
		return
	}
	err = fmt.Errorf("[msg : xmlUnmarshalError] [rawReturn : %s] [params : %s] [sign : %s]",
		string(rawRet), str, sign)
	return
}

// RefundQuery return refundQueryResult
func (pcf *Pay) RefundQuery(p *RefundParams) (refundQueryResult RefundQueryResult, xmlBody []byte, err error) {
	nonceStr := util.RandomStr(32)
	param := make(map[string]interface{})
	param["appid"] = pcf.AppID
	param["mch_id"] = pcf.PayMchID
	param["out_refund_no"] = p.OutRefundNo
	param["nonce_str"] = nonceStr

	str, sign := pcf.Sign(param)
	log.Println("RefundQuery")
	log.Println(str, sign)
	request := refundQueryRequest{
		AppID:       pcf.AppID,
		MchID:       pcf.PayMchID,
		OutRefundNo: p.OutRefundNo,
		NonceStr:    nonceStr,
		Sign:        sign,
	}
	xmlBody, err = util.PostXML(refundQueryURL, request)
	if err != nil {
		return
	}
	err = xml.Unmarshal(xmlBody, &refundQueryResult)
	if err != nil {
		return
	}
	if refundQueryResult.ReturnCode == "SUCCESS" {
		//query success
		if refundQueryResult.ResultCode == "SUCCESS" {
			err = nil
			return
		}
		err = errors.New(refundQueryResult.ErrCode + refundQueryResult.ErrCodeDes)
		return
	}
	err = errors.New("[msg : xmlUnmarshalError] [rawReturn : " + string(xmlBody) + "] [params : " + str + "] [sign : " + sign + "]")
	return
}
