package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func nickname() string {
	adjs := []string{"飞翔", "逐风", "无畏", "低调", "温柔", "清醒", "闪电", "暴走", "潇洒", "沉默",
		"热血", "冷静", "追光", "孤独", "迷途", "滚烫", "平静", "勇敢", "机智", "自在",
		"飘逸", "执着", "温暖", "高冷", "炽热", "清澈", "朴素", "恬淡", "灵动", "轻盈",
		"狂野", "优雅", "神秘", "纯真", "深沉", "活泼", "安静", "张扬", "内敛", "奔放",
		"细腻", "粗犷", "精致", "豪放", "温润", "锐利", "柔和", "刚烈", "清新", "浓郁"}
	nouns := []string{"小哥", "姑娘", "船长", "骑士", "旅人", "诗人", "画师", "黑客", "捕风者", "观星者",
		"远行者", "逐梦者", "程序员", "航海家", "筑梦者", "修行者", "开拓者", "探路者",
		"听风者", "赶路人", "追梦人", "夜行者", "晨光者", "月光者", "星光者", "阳光者",
		"风语者", "雨行者", "雪舞者", "花语者", "鸟语者", "鱼游者", "蝶舞者", "蜂鸣者",
		"书虫", "码农", "设计师", "艺术家", "音乐家", "舞蹈家", "摄影师", "导演", "编剧",
		"探险家", "科学家", "发明家", "思想家", "哲学家", "教育家", "医生", "律师", "记者"}

	pick := func(n int) int {
		if n <= 1 {
			return 0
		}
		var b [4]byte
		if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
			return int(time.Now().UnixNano()) % n
		}
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		return int(v % uint32(n))
	}
	return adjs[pick(len(adjs))] + "的" + nouns[pick(len(nouns))]
}

func b32e(data []byte) string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return strings.ToLower(enc.EncodeToString(data))
}
func b64ue(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}
func b64ud(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}

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

func parseDNSAddr(addr string) (host string, port int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		portStr = ""
	}

	if host == "" {
		host = "127.0.0.1"
	}

	port = 5335
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	return host, port
}

type DNSChat struct {
	group []byte
	name  string
	sid   []byte
	key   []byte

	resolver   *net.Resolver
	serverAddr string
	timeout    time.Duration
	verbose    bool
}

func (dc *DNSChat) debug(format string, args ...interface{}) {
	if dc.verbose {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

func NewDNSChat(dnsHost string, dnsPort int, group, name string, verbose bool) (*DNSChat, error) {
	sid := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, sid); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(group))
	key := sum[:]

	serverAddr := fmt.Sprintf("%s:%d", dnsHost, dnsPort)
	d := &net.Dialer{Timeout: 2 * time.Second}
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return d.DialContext(ctx, "udp", serverAddr)
	}}
	return &DNSChat{group: []byte(group), name: name, sid: sid, key: key, resolver: r, serverAddr: serverAddr, timeout: 5 * time.Second, verbose: verbose}, nil
}

func buildQName(labels []string) string {
	s := strings.Join(labels, ".")
	return strings.TrimRight(s, ".") + "."
}

func (dc *DNSChat) queryTXT(qname string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dc.timeout)
	defer cancel()
	txts, err := dc.resolver.LookupTXT(ctx, qname)
	if err != nil || len(txts) == 0 {
		return nil, errors.New("no answer")
	}
	return []byte(strings.Join(txts, "")), nil
}

func (dc *DNSChat) SendMessage(message string) {
	data := append([]byte(dc.name), 0)
	data = append(data, []byte(message)...)
	const chunkSize = 80
	totalChunks := (len(data) + chunkSize - 1) / chunkSize
	dc.debug("[发送] 会话: %x; 消息: \"%s\"; 分块数: %d;", dc.sid, message, totalChunks)
	for seq, i := 0, 0; i < len(data); seq, i = seq+1, i+chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		nonce := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			continue
		}
		ct, err := aese(dc.key, nonce, chunk, dc.sid)
		if err != nil {
			continue
		}
		payload := b64ue(ct)
		payloadLabels := make([]string, 0, (len(payload)+29)/30)
		for j := 0; j < len(payload); j += 30 {
			k := j + 30
			if k > len(payload) {
				k = len(payload)
			}
			payloadLabels = append(payloadLabels, payload[j:k])
		}
		labels := []string{b32e(dc.group), b32e(dc.sid), "u", fmt.Sprintf("%d", seq), b32e(nonce)}
		labels = append(labels, payloadLabels...)
		qname := buildQName(labels)
		_, _ = dc.queryTXT(qname)
	}
}

func (dc *DNSChat) PollMessage() (string, bool) {
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", false
	}
	labels := []string{b32e(dc.group), b32e(dc.sid), "p", "0", b32e(nonce)}
	qname := buildQName(labels)
	resp, err := dc.queryTXT(qname)
	if err != nil || len(resp) == 0 {
		return "", false
	}
	ct, err := b64ud(string(resp))
	if err != nil {
		return "", false
	}
	pt, err := aesd(dc.key, nonce, ct, dc.sid)
	if err != nil || len(pt) == 0 {
		return "", false
	}
	var formattedMsg string
	if idx := bytes.IndexByte(pt, 0); idx >= 0 {
		formattedMsg = fmt.Sprintf("%s: %s", string(pt[:idx]), string(pt[idx+1:]))
	} else {
		formattedMsg = string(pt)
	}
	dc.debug("[接收] 会话: %x; 数据长度: %d;", dc.sid, len(pt))
	dc.debug("       内容: %s", formattedMsg)
	return formattedMsg, true
}

func (dc *DNSChat) ReceiveLoop(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if msg, ok := dc.PollMessage(); ok {
				fmt.Println(msg)
			}
		case <-stop:
			return
		}
	}
}

func main() {
	var name, group, dns, dnsHost string
	var dnsPort int
	var interval float64
	var verbose bool
	flag.StringVar(&name, "name", nickname(), "昵称")
	flag.StringVar(&group, "group", "default", "分组ID")
	flag.StringVar(&dns, "dns", "127.0.0.1:5335", "DNS 服务器 (host:port 格式)")
	flag.Float64Var(&interval, "interval", 0.25, "轮询间隔(秒)")
	flag.BoolVar(&verbose, "verbose", false, "调试模式")
	flag.Parse()

	dnsHost, dnsPort = parseDNSAddr(dns)

	cli, err := NewDNSChat(dnsHost, dnsPort, group, name, verbose)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("[你是 '%s']\n", name)
	fmt.Printf("[连接到 %s:%d, 分组 '%s']\n", dnsHost, dnsPort, group)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); cli.ReceiveLoop(time.Duration(interval*1000)*time.Millisecond, stop) }()

	reader := bufio.NewScanner(os.Stdin)
	for reader.Scan() {
		line := strings.TrimRight(reader.Text(), "\n")
		if line != "" {
			cli.SendMessage(line)
		}
	}
	close(stop)
	wg.Wait()
}
