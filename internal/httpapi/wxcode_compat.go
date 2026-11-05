package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"yyb_go/internal/eventlog"
	"yyb_go/internal/store"
)

// wxcode 兼容层（方案 A）：只增加两条对外的旧版线格式入口，不改动任何
// 既有取码逻辑。底层一律复用 a.invokeWXApp + a.invokeGetCode，因此熔断，
// 登录预算、编队、事件日志与 /wxapp/getCode 完全一致。
//
//	GET  /login?appId=wx...&ref=<openid|pcmgr:xxx|数字ID>
//	POST /login {"app_id":"wx...","ref":"..."}
//	GET  /instances
//
// 返回体沿用 wxcode 的字段名，方便老脚本零改造接入。

var (
	wxHexRe    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	wxB64Re    = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)
	wxB64URLRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	wxAlnumRe  = regexp.MustCompile(`^[A-Za-z0-9]+$`)
)

// classifyWXCode 与 wxcode 原来的 codeType 分类保持一致。
func classifyWXCode(code string) string {
	switch {
	case code == "":
		return "invalid"
	case wxHexRe.MatchString(code):
		return "hex"
	case wxB64Re.MatchString(code):
		return "base64"
	case wxB64URLRe.MatchString(code):
		return "base64url"
	case wxAlnumRe.MatchString(code):
		return "alnum"
	default:
		return "other"
	}
}

// handleUnifiedLogin 挂在 /login 上，先分流再落到原来的控制台登录：
//
//   - GET  /login?appId=             -> wxcode 取码
//   - POST JSON 只有 app_id 无 username -> wxcode 取码
//   - 其余（登录页、表单登录、logout 等）-> a.handleLogin
func (a *App) handleUnifiedLogin(w http.ResponseWriter, r *http.Request) {
	appID := strings.TrimSpace(r.URL.Query().Get("appId"))
	if appID == "" {
		appID = strings.TrimSpace(r.URL.Query().Get("app_id"))
	}
	if appID != "" {
		a.handleWXCodeCompat(w, r)
		return
	}
	if r.Method == http.MethodPost {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err == nil && len(body) > 0 {
			var probe map[string]json.RawMessage
			if json.Unmarshal(body, &probe) == nil {
				_, hasAppID := probe["app_id"]
				_, hasUsername := probe["username"]
				_, hasPassword := probe["password"]
				if hasAppID && !hasUsername && !hasPassword {
					a.handleWXCodeCompat(w, r)
					return
				}
			}
		}
	}
	a.handleLogin(w, r)
}

// handleWXCodeCompat 是 wxcode 线格式的取码入口，永远以 HTTP 200 返回，
// 用 err 字段表示成败（老脚本是按这个约定解析的）。
func (a *App) handleWXCodeCompat(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeProtocol(w, r) {
		return
	}

	appID := strings.TrimSpace(r.URL.Query().Get("appId"))
	if appID == "" {
		appID = strings.TrimSpace(r.URL.Query().Get("app_id"))
	}
	ref := strings.TrimSpace(r.URL.Query().Get("ref"))

	if r.Method == http.MethodPost {
		var body struct {
			AppID string `json:"app_id"`
			Ref   string `json:"ref"`
		}
		if err := decodeOptionalJSON(r, &body); err != nil {
			writeRawJSON(w, http.StatusOK, map[string]any{"err": -1, "msg": "invalid JSON: " + err.Error()})
			return
		}
		if s := strings.TrimSpace(body.AppID); s != "" {
			appID = s
		}
		if s := strings.TrimSpace(body.Ref); s != "" {
			ref = s
		}
	}

	if appID == "" {
		writeRawJSON(w, http.StatusOK, map[string]any{"err": -1, "msg": "appId is required"})
		return
	}

	acc, err := a.compatAccount(r, ref)
	if err != nil {
		writeRawJSON(w, http.StatusOK, map[string]any{"err": -1, "msg": err.Error(), "appId": appID})
		return
	}

	ctx := withWXOperationContext(r.Context(), eventlog.OpGetCode)
	result, callErr := a.invokeWXApp(ctx, acc, appID, nil, a.invokeGetCode)
	if callErr != nil {
		writeRawJSON(w, http.StatusOK, map[string]any{
			"err": -1, "msg": callErr.Error(), "appId": appID,
			"status": "fail", "openid": acc.OpenID,
		})
		return
	}

	code := stringFromAny(result["code"])
	writeRawJSON(w, http.StatusOK, map[string]any{
		"err": 0, "msg": "success", "appId": appID,
		"status": "ok", "code": code,
		"codeType": classifyWXCode(code), "codeLength": len(code),
		"openid": acc.OpenID,
	})
}

// compatAccount 解析账号：显式 ref 优先，否则在可见账号里挑默认（存活优先、
// 其次最近更新）。未传 ref 时不再报 multiple accounts，保持老脚本可用。
func (a *App) compatAccount(r *http.Request, ref string) (*store.WechatAccount, error) {
	if ref != "" {
		acc, err := a.db.ResolveAccount(r.Context(), ref)
		if err != nil {
			return nil, err
		}
		if !a.accountVisible(r, acc.ID) {
			return nil, errors.New("account not found: " + ref)
		}
		return acc, nil
	}
	accounts, err := a.visibleAccounts(r)
	if err != nil {
		return nil, err
	}
	switch len(accounts) {
	case 0:
		return nil, errors.New("no wechat account configured (scan a QR in the console first)")
	case 1:
		return accounts[0], nil
	}
	best := accounts[0]
	for _, acc := range accounts[1:] {
		if betterWXDefaultAccount(acc, best) {
			best = acc
		}
	}
	return best, nil
}

// betterWXDefaultAccount 存活账号优先，其次最近更新。
func betterWXDefaultAccount(candidate, current *store.WechatAccount) bool {
	cAlive := accountStatus(candidate) == "alive"
	curAlive := accountStatus(current) == "alive"
	if cAlive != curAlive {
		return cAlive
	}
	return candidate.UpdatedAt > current.UpdatedAt
}

// handleWXCompatInstances 用 wxcode 的实例列表形状返回账号，供老脚本枚举。
// 可见范围与 /integration/accounts 一致：无浏览器会话（脚本/令牌）看全部，
// 带会话则按账号归属过滤。
func (a *App) handleWXCompatInstances(w http.ResponseWriter, r *http.Request) {
	accounts, err := a.visibleAccounts(r)
	if err != nil {
		writeRawJSON(w, http.StatusInternalServerError, map[string]any{"err": -500, "msg": err.Error()})
		return
	}
	instances := make([]map[string]any, 0, len(accounts))
	for _, acc := range accounts {
		nickname := ""
		if acc.Nickname != nil {
			nickname = *acc.Nickname
		}
		instances = append(instances, map[string]any{
			"packageName": "com.tencent.mm",
			"userId":      0,
			"version":     "8.0.76",
			"port":        8000,
			"openid":      acc.OpenID,
			"nickname":    nickname,
		})
	}
	writeRawJSON(w, http.StatusOK, map[string]any{
		"count": len(instances), "instances": instances,
		"current": "com.tencent.mm", "currentUserId": 0,
	})
}
