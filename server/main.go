package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"dnsay/shared"

	"github.com/miekg/dns"
)

type parsed struct {
	grp, sid, payload []byte
	dir               string
	seq, total        int
}

func parseQName(qname string) (*parsed, error) {
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	if len(labels) < 5 {
		return nil, errors.New("qname too short")
	}
	grp, err := shared.B32Decode(labels[0])
	if err != nil {
		return nil, err
	}
	sid, err := shared.B32Decode(labels[1])
	if err != nil {
		return nil, err
	}
	dir := labels[2]
	parts := strings.SplitN(labels[3], "-", 2)
	seq, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, err
	}
	total := 1
	if len(parts) > 1 {
		total, err = strconv.Atoi(parts[1])
		if err != nil {
			return nil, err
		}
	}
	// labels[4] is a query nonce for DNS uniqueness, not used by server
	var payload []byte
	if len(labels) > 5 {
		payload, err = shared.B32Decode(strings.Join(labels[5:], ""))
		if err != nil {
			return nil, err
		}
	}
	return &parsed{grp: grp, sid: sid, dir: dir, seq: seq, total: total, payload: payload}, nil
}

type msgBuffer struct {
	chunks map[int][]byte
	total  int
	bytes  int
}

type session struct {
	grp    []byte
	name   string
	downq  [][]byte
	last   int64
	msgBuf *msgBuffer
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

func (m *SessionManager) popMessages(sid []byte, maxCount, maxBytes int) [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[string(sid)]
	if s == nil || len(s.downq) == 0 {
		return nil
	}
	var msgs [][]byte
	var totalBytes int
	for len(s.downq) > 0 && len(msgs) < maxCount {
		msg := s.downq[0]
		cost := len(msg) + 2
		if totalBytes+cost > maxBytes && len(msgs) > 0 {
			break
		}
		msgs = append(msgs, msg)
		totalBytes += cost
		s.downq = s.downq[1:]
	}
	return msgs
}

func (m *SessionManager) addChunk(sid []byte, seq, total int, data []byte) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[string(sid)]
	if s == nil {
		return nil
	}
	if s.msgBuf == nil || s.msgBuf.total != total || seq == 0 {
		s.msgBuf = &msgBuffer{chunks: make(map[int][]byte), total: total}
	}
	if prev, ok := s.msgBuf.chunks[seq]; ok {
		s.msgBuf.bytes -= len(prev)
	}
	s.msgBuf.chunks[seq] = data
	s.msgBuf.bytes += len(data)
	if s.msgBuf.bytes > maxUploadTotal {
		s.msgBuf = nil
		return nil
	}
	if len(s.msgBuf.chunks) == s.msgBuf.total {
		var result []byte
		for i := 0; i < total; i++ {
			result = append(result, s.msgBuf.chunks[i]...)
		}
		s.msgBuf = nil
		return result
	}
	return nil
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

func (m *SessionManager) hasName(sid []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[string(sid)]
	return s != nil && s.name != ""
}

func (m *SessionManager) remove(sid []byte) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := string(sid)
	s := m.sessions[k]
	if s == nil {
		return ""
	}
	name := s.name
	delete(m.sessions, k)
	return name
}

func (m *SessionManager) register(sid, grp []byte, name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := string(sid)
	for id, s := range m.sessions {
		if id != k && s.grp != nil && string(s.grp) == string(grp) && s.name == name {
			return false
		}
	}
	s := m.sessions[k]
	if s == nil {
		s = &session{}
		m.sessions[k] = s
	}
	s.grp = grp
	s.name = name
	s.last = time.Now().Unix()
	return true
}

const (
	maxTXTLength = 200
	maxPollCount = 10
	maxPollBytes = 4096
	maxUploadChunks    = 64
	maxUploadChunkSize = 256
	maxUploadTotal     = 4096 + shared.NonceSize + shared.GCMTagSize
	maxNameBytes       = 64
)

type chatHandler struct {
	mgr     *SessionManager
	verbose bool
}

func (h *chatHandler) debug(format string, args ...interface{}) {
	if h.verbose {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

func validUpload(info *parsed) bool {
	if info.total < 1 || info.total > maxUploadChunks {
		return false
	}
	if info.seq < 0 || info.seq >= info.total {
		return false
	}
	if len(info.payload) == 0 || len(info.payload) > maxUploadChunkSize {
		return false
	}
	return true
}

func (h *chatHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}
	q := r.Question[0]
	if q.Qtype != dns.TypeTXT {
		h.replyText(w, r, q.Name, shared.RespOK)
		return
	}
	info, err := parseQName(q.Name)
	if err != nil {
		h.replyText(w, r, q.Name, shared.RespOK)
		return
	}
	h.mgr.touch(info.sid, info.grp)
	switch info.dir {
	case shared.DirUpload:
		if !validUpload(info) {
			h.replyText(w, r, q.Name, shared.RespBad)
			return
		}
		if info.total <= 1 {
			h.debug("[接收] 路由: %x; 会话: %x; 数据长度: %d;", info.grp, info.sid, len(info.payload))
			h.mgr.broadcast(info.grp, info.sid, info.payload)
		} else {
			h.debug("[接收] 路由: %x; 会话: %x; 块: %d/%d; 单次块长度: %d;", info.grp, info.sid, info.seq+1, info.total, len(info.payload))
			complete := h.mgr.addChunk(info.sid, info.seq, info.total, info.payload)
			if complete != nil {
				h.debug("[接收] 路由: %x; 会话: %x; 完整块长度: %d;", info.grp, info.sid, len(complete))
				h.mgr.broadcast(info.grp, info.sid, complete)
			}
		}
		if h.mgr.hasName(info.sid) {
			h.replyText(w, r, q.Name, shared.RespOK)
		} else {
			h.replyText(w, r, q.Name, shared.RespUnreg)
		}
	case shared.DirPoll:
		msgs := h.mgr.popMessages(info.sid, maxPollCount, maxPollBytes)
		var buf []byte
		for _, msg := range msgs {
			buf = append(buf, byte(len(msg)>>8), byte(len(msg)))
			buf = append(buf, msg...)
		}
		if len(msgs) > 0 {
			h.debug("[发送] 会话: %x; 消息数: %d; 总长度: %d;", info.sid, len(msgs), len(buf))
		}
		h.replyData(w, r, q.Name, buf)
	case shared.DirJoin:
		if len(info.payload) == 0 || len(info.payload) > maxNameBytes {
			h.replyText(w, r, q.Name, shared.RespBad)
			return
		}
		regName := string(info.payload)
		if h.mgr.register(info.sid, info.grp, regName) {
			h.debug("[注册] 路由: %x; 会话: %x; 昵称: %s;", info.grp, info.sid, regName)
			h.replyText(w, r, q.Name, shared.RespOK)
		} else {
			h.debug("[重名] 路由: %x; 会话: %x; 昵称: %s;", info.grp, info.sid, regName)
			h.replyText(w, r, q.Name, shared.RespDup)
		}
	case shared.DirLeave:
		leftName := h.mgr.remove(info.sid)
		h.debug("[离开] 路由: %x; 会话: %x; 昵称: %s;", info.grp, info.sid, leftName)
		h.replyText(w, r, q.Name, shared.RespOK)
	default:
		h.replyText(w, r, q.Name, shared.RespNoop)
	}
}

func (h *chatHandler) replyText(w dns.ResponseWriter, r *dns.Msg, name, text string) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{text}})
	_ = w.WriteMsg(m)
}

func (h *chatHandler) replyData(w dns.ResponseWriter, r *dns.Msg, name string, data []byte) {
	m := new(dns.Msg)
	m.SetReply(r)
	if len(data) == 0 {
		m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{""}})
	} else {
		enc := shared.B64URLEncode(data)
		for i := 0; i < len(enc); i += maxTXTLength {
			end := i + maxTXTLength
			if end > len(enc) {
				end = len(enc)
			}
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{enc[i:end]}})
		}
	}
	_ = w.WriteMsg(m)
}

func startPeriodicCleanup(ctx context.Context, mgr *SessionManager, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = mgr.cleanup()
		case <-ctx.Done():
			return
		}
	}
}

func main() {
	var bind string
	var port, timeout int
	var verbose bool
	flag.StringVar(&bind, "bind", "0.0.0.0", "绑定地址")
	flag.IntVar(&port, "port", 5335, "监听端口")
	flag.IntVar(&timeout, "timeout", 300, "会话空闲超时 (秒)")
	flag.BoolVar(&verbose, "verbose", false, "调试模式")
	flag.Parse()
	if port <= 0 || port > 65535 {
		fmt.Fprintf(os.Stderr, "无效端口: %d\n", port)
		os.Exit(1)
	}
	if timeout <= 0 {
		fmt.Fprintf(os.Stderr, "无效 timeout: %d, 必须大于 0\n", timeout)
		os.Exit(1)
	}
	mgr := NewSessionManager(timeout)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go startPeriodicCleanup(ctx, mgr, 10*time.Second)
	handler := &chatHandler{mgr: mgr, verbose: verbose}
	addr := net.JoinHostPort(bind, strconv.Itoa(port))
	udpConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "UDP 监听失败 %s: %v\n", addr, err)
		os.Exit(1)
	}
	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		_ = udpConn.Close()
		fmt.Fprintf(os.Stderr, "TCP 监听失败 %s: %v\n", addr, err)
		os.Exit(1)
	}
	udpSrv := &dns.Server{PacketConn: udpConn, Handler: handler}
	tcpSrv := &dns.Server{Listener: tcpLn, Handler: handler}
	errc := make(chan error, 2)
	go func() {
		if err := udpSrv.ActivateAndServe(); err != nil {
			errc <- fmt.Errorf("UDP 服务失败: %w", err)
		}
	}()
	go func() {
		if err := tcpSrv.ActivateAndServe(); err != nil {
			errc <- fmt.Errorf("TCP 服务失败: %w", err)
		}
	}()
	fmt.Printf("DNS 服务运行中\n%s (UDP/TCP)\n", addr)
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	exitCode := 0
	select {
	case <-sigc:
	case err := <-errc:
		fmt.Fprintln(os.Stderr, err)
		exitCode = 1
	}
	cancel()
	_ = udpSrv.ShutdownContext(context.Background())
	_ = tcpSrv.ShutdownContext(context.Background())
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
