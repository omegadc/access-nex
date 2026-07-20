package server

// OIDC back-channel and front-channel logout: when a user's access-nex
// session ends, every application they've authorized (per the grants table)
// that registered a logout URI is told about it, so signing out of
// access-nex signs the user out of those apps too.
//
//   - Back-channel: a server-to-server POST of a signed "logout token"
//     (OpenID Connect Back-Channel Logout 1.0). Fire-and-forget — the user
//     isn't kept waiting on another service's network round trip.
//   - Front-channel: the logout confirmation page loads each app's
//     front-channel logout URI in a hidden iframe, so it runs in the user's
//     own browser session with that app (OpenID Connect Front-Channel
//     Logout 1.0).
import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/omegadc/access-nex/internal/models"
	"github.com/omegadc/access-nex/internal/secrets"
)

// notifyBackchannelLogout POSTs a logout token to every app the subject has
// used that registered a backchannel_logout_uri. Runs in the background so
// the user's own logout isn't delayed by another service being slow/down.
func (s *Server) notifyBackchannelLogout(subject string) {
	apps, err := s.store.ListAppsForSubject(subject)
	if err != nil {
		s.log.Error("backchannel logout: list apps", "error", err)
		return
	}
	for _, a := range apps {
		if a.BackchannelLogoutURI == "" {
			continue
		}
		go s.sendBackchannelLogout(a, subject)
	}
}

func (s *Server) sendBackchannelLogout(app *models.App, subject string) {
	token, err := s.signJWT(map[string]any{
		"iss": s.issuer, "sub": subject, "aud": app.ID,
		"iat": time.Now().Unix(), "jti": secrets.RandomToken(16),
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	})
	if err != nil {
		s.log.Error("backchannel logout: sign token", "client_id", app.ID, "error", err)
		return
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.PostForm(app.BackchannelLogoutURI, url.Values{"logout_token": {token}})
	if err != nil {
		s.log.Warn("backchannel logout: delivery failed", "client_id", app.ID, "error", err)
		s.store.Audit("backchannel_logout_failed", subject, app.ID, "", err.Error())
		return
	}
	resp.Body.Close()
	s.store.Audit("backchannel_logout_sent", subject, app.ID, "", resp.Status)
}

// frontchannelLogoutURIs returns the logout URIs to load in browser iframes.
func (s *Server) frontchannelLogoutURIs(subject string) []string {
	apps, err := s.store.ListAppsForSubject(subject)
	if err != nil {
		return nil
	}
	var uris []string
	for _, a := range apps {
		if a.FrontchannelLogoutURI != "" {
			uris = append(uris, a.FrontchannelLogoutURI)
		}
	}
	return uris
}

// renderFrontchannelLogoutPage shows a brief confirmation while each app's
// front-channel logout URI loads in a hidden iframe, then continues to
// redirectTo (or a default message page if empty).
func (s *Server) renderFrontchannelLogoutPage(w http.ResponseWriter, uris []string, redirectTo string) {
	iframes := ""
	for _, u := range uris {
		iframes += `<iframe src="` + esc(u) + `" style="display:none" width="0" height="0"></iframe>`
	}
	continueScript := `<p>Signed out. <a href="/">Continue</a></p>`
	if redirectTo != "" {
		continueScript = `<script>setTimeout(function(){ window.location = ` + jsonString(redirectTo) + `; }, 400);</script>
<p>Signed out. <a href="` + esc(redirectTo) + `">Continue</a></p>`
	}
	page := `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Signing Out — Access-Nex</title>` + loginStyle + `</head><body>
<div class="card"><div class="logo">🔐 Access-Nex</div>` + continueScript + `</div>
` + iframes + `
</body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

func jsonString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
