package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

func b32d(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", "")
	enc := base32.StdEncoding
	u := strings.ToUpper(s)
	if m := len(u) % 8; m != 0 {
		u += strings.Repeat("=", 8-m)
	}
	return enc.DecodeString(u)
}
func b64ud(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}
func b64ue(b []byte) string { return base64.URLEncoding.EncodeToString(b) }
func aese(key, nonce, data, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return g.Seal(nil, nonce, data, aad), nil
}
func aesd(key, nonce, data, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, data, aad)
}
func deriveKey(group []byte) []byte { sum := sha256.Sum256(group); return sum[:] }

type parsed struct {
	grp, sid, nonce, payload []byte
	dir                      string
	seq                      int
}

func parseQName(qname string) (*parsed, error) {
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	if len(labels) < 5 {
		return nil, errors.New("short")
	}
	grp, err := b32d(labels[0])
	if err != nil {
		return nil, err
	}
	sid, err := b32d(labels[1])
	if err != nil {
		return nil, err
	}
	dir := labels[2]
	var seq int
	if _, err := fmt.Sscanf(labels[3], "%d", &seq); err != nil {
		return nil, err
	}
	nonce, err := b32d(labels[4])
	if err != nil {
		return nil, err
	}
	var payload []byte
	if len(labels) > 5 {
		payload, err = b64ud(strings.Join(labels[5:], ""))
		if err != nil {
			return nil, err
		}
	}
	return &parsed{grp: grp, sid: sid, dir: dir, seq: seq, nonce: nonce, payload: payload}, nil
}

type session struct {
	grp   []byte
	downq [][]byte
	last  int64
}
type SessionManager struct {
	mu       sync.Mutex
	timeout  int64
	sessions map[string]*session
}

func NewSessionManager(timeout int) *SessionManager {
	return &SessionManager{timeout: int64(timeout), sessions: make(map[string]*session)}
}
func (m *SessionManager) touch(sid []byte, grp []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := string(sid)
	s := m.sessions[k]
	if s == nil {
		s = &session{}
		m.sessions[k] = s
	}
	s.last = time.Now().Unix()
	if grp != nil {
		s.grp = grp
	}
}
func (m *SessionManager) get(sid []byte) *session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[string(sid)]
}
func (m *SessionManager) cleanup() int {
	now := time.Now().Unix()
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for k, s := range m.sessions {
		if now-s.last > m.timeout {
			delete(m.sessions, k)
			removed++
		}
	}
	return removed
}
func (m *SessionManager) broadcast(grp []byte, senderSid []byte, msg []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for sid, s := range m.sessions {
		if s.grp != nil && string(s.grp) == string(grp) && sid != string(senderSid) {
			s.downq = append(s.downq, msg)
		}
	}
}

type chatHandler struct {
	mgr       *SessionManager
	maxLength int
	verbose   bool
}

func (h *chatHandler) debug(format string, args ...interface{}) {
	if h.verbose {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

func (h *chatHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	if q.Qtype != dns.TypeTXT {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{"ok"}})
		_ = w.WriteMsg(m)
		return
	}
	info, err := parseQName(q.Name)
	if err != nil {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{"ok"}})
		_ = w.WriteMsg(m)
		return
	}
	key := deriveKey(info.grp)
	h.mgr.touch(info.sid, info.grp)
	switch info.dir {
	case "u":
		pt, err := aesd(key, info.nonce, info.payload, info.sid)
		if err != nil {
			h.replyText(w, r, q.Name, "bad")
			return
		}
		h.debug("[接收] 分组: %s; 会话: %x; 消息长度: %d;", string(info.grp), info.sid, len(pt))
		if len(pt) > 0 {
			h.debug("       内容: %s", string(pt))
		}
		h.mgr.broadcast(info.grp, info.sid, pt)
		h.debug("[广播] 分组: %s;", string(info.grp))
		ack := []byte{'o', 'k', byte(info.seq >> 24), byte(info.seq >> 16), byte(info.seq >> 8), byte(info.seq)}
		h.replyEncrypted(w, r, q.Name, key, info.nonce, ack, info.sid)
		return
	case "p":
		s := h.mgr.get(info.sid)
		var msg []byte
		if s != nil && len(s.downq) > 0 {
			msg = s.downq[0]
			s.downq = s.downq[1:]
			h.debug("[发送] 会话: %x; 消息长度: %d;", info.sid, len(msg))
			if len(msg) > 0 {
				h.debug("       内容: %s;", string(msg))
			}
		} else {
			msg = []byte{}
		}
		h.replyEncrypted(w, r, q.Name, key, info.nonce, msg, info.sid)
		return
	default:
		h.replyText(w, r, q.Name, "noop")
		return
	}
}
func (h *chatHandler) replyText(w dns.ResponseWriter, r *dns.Msg, name, text string) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{text}})
	_ = w.WriteMsg(m)
}
func (h *chatHandler) replyEncrypted(w dns.ResponseWriter, r *dns.Msg, name string, key, nonce, data, sid []byte) {
	ct, err := aese(key, nonce, data, sid)
	if err != nil {
		h.replyText(w, r, name, "bad")
		return
	}
	enc := b64ue(ct)
	m := new(dns.Msg)
	m.SetReply(r)
	for i := 0; i < len(enc); i += h.maxLength {
		end := i + h.maxLength
		if end > len(enc) {
			end = len(enc)
		}
		m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{enc[i:end]}})
	}
	_ = w.WriteMsg(m)
}

func startPeriodicCleanup(mgr *SessionManager, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		_ = mgr.cleanup()
	}
}

func startServer(srv *dns.Server) {
	_ = srv.ListenAndServe()
}

func main() {
	var bind string
	var port, maxLength, timeout int
	var verbose bool
	flag.StringVar(&bind, "bind", "0.0.0.0", "绑定地址")
	flag.IntVar(&port, "port", 5335, "监听端口")
	flag.IntVar(&maxLength, "max-length", 200, "TXT 记录最大长度")
	flag.IntVar(&timeout, "timeout", 300, "会话空闲超时 (秒)")
	flag.BoolVar(&verbose, "verbose", false, "调试模式")
	flag.Parse()
	mgr := NewSessionManager(timeout)
	go startPeriodicCleanup(mgr, 10*time.Second)
	handler := &chatHandler{mgr: mgr, maxLength: maxLength, verbose: verbose}
	udpSrv := &dns.Server{Addr: fmt.Sprintf("%s:%d", bind, port), Net: "udp", Handler: handler}
	tcpSrv := &dns.Server{Addr: fmt.Sprintf("%s:%d", bind, port), Net: "tcp", Handler: handler}
	go startServer(udpSrv)
	go startServer(tcpSrv)
	fmt.Printf("DNS 服务运行中\n%s:%d (UDP/TCP)\n", bind, port)
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	<-sigc
	_ = udpSrv.ShutdownContext(context.Background())
	_ = tcpSrv.ShutdownContext(context.Background())
}
