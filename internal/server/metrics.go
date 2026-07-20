package server

// Prometheus metrics: HTTP traffic shape and the security-relevant counters
// an operator actually wants to alert on (login failures, DPoP rejections,
// token issuance by grant type) beyond what the audit log gives them.
//
// The /metrics endpoint itself is unauthenticated, following standard
// Prometheus practice — it's meant to be scraped from inside a private
// network, not exposed publicly; see the README for the operational note.

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metrics struct {
	registry *prometheus.Registry

	httpRequests *prometheus.CounterVec
	httpDuration *prometheus.HistogramVec

	loginResults   *prometheus.CounterVec // result=success|failed|locked
	tokensIssued   *prometheus.CounterVec // grant_type=...
	dpopRejections *prometheus.CounterVec // reason=...
}

func newMetrics() *metrics {
	reg := prometheus.NewRegistry()
	m := &metrics{
		registry: reg,
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "access_nex_http_requests_total",
			Help: "HTTP requests by route, method, and status code.",
		}, []string{"route", "method", "status"}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "access_nex_http_request_duration_seconds",
			Help:    "HTTP request latency by route.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route"}),
		loginResults: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "access_nex_login_attempts_total",
			Help: "Login attempts by outcome.",
		}, []string{"result"}),
		tokensIssued: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "access_nex_tokens_issued_total",
			Help: "Tokens issued by grant type.",
		}, []string{"grant_type"}),
		dpopRejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "access_nex_dpop_rejections_total",
			Help: "Rejected DPoP proofs by reason.",
		}, []string{"reason"}),
	}
	reg.MustRegister(m.httpRequests, m.httpDuration, m.loginResults, m.tokensIssued, m.dpopRejections)
	return m
}

// statusRecorder captures the status code a handler wrote, since
// http.ResponseWriter doesn't expose it after the fact.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// withMetrics wraps the mux to record request counts/latency, labeled by
// the *registered route pattern* (e.g. "GET /admin"), not the raw request
// path — an unauthenticated attacker choosing arbitrary paths must not be
// able to mint unbounded label combinations (Prometheus cardinality/memory
// exhaustion). mux.Handler resolves the pattern without re-running it.
func (s *Server) withMetrics(mux *http.ServeMux, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		if pattern == "" {
			pattern = "unmatched"
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.metrics.httpRequests.WithLabelValues(pattern, r.Method, strconv.Itoa(rec.status)).Inc()
		s.metrics.httpDuration.WithLabelValues(pattern).Observe(time.Since(start).Seconds())
	})
}

func (s *Server) handleMetrics() http.Handler {
	return promhttp.HandlerFor(s.metrics.registry, promhttp.HandlerOpts{})
}
