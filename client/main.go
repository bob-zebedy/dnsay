package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"dnsay/shared"

	"github.com/gdamore/tcell/v2"
	"github.com/mattn/go-runewidth"
	"github.com/rivo/tview"
)

const (
	colorSelf    = "#9ECE6A" // 柔绿 — 自己的名字
	colorSep     = "#87CEEB" // 天蓝 — 分隔线
	colorInfo    = "#7AA2F7" // 靛蓝 — 连接/分组信息
	colorTitle   = "#E0AF68" // 琥珀 — 标题文字
	colorError   = "#F7768E" // 珊瑚 — 错误提示
	colorSelfTUI = 0xEAEDF7  // 输入框文字
)

var peerColors = []string{
	"#BB9AF7", // 薰衣草
	"#7DCFFF", // 天蓝
	"#FF9E64", // 暖橙
	"#F7768E", // 珊瑚粉
	"#73DACA", // 青碧
	"#E0AF68", // 琥珀
	"#B4F9F8", // 薄荷
	"#C0CAF5", // 长春花
	"#FF79C6", // 玫红
	"#D5A6BD", // 藕荷
}

func nickname() string {
	adjs := []string{"飞翔", "逐风", "无畏", "低调", "温柔", "清醒", "闪电", "暴走", "潇洒", "沉默",
		"热血", "冷静", "追光", "孤独", "迷途", "滚烫", "平静", "勇敢", "机智", "自在",
		"飘逸", "执着", "温暖", "高冷", "炽热", "清澈", "朴素", "恬淡", "灵动", "轻盈",
		"狂野", "优雅", "神秘", "纯真", "深沉", "活泼", "安静", "张扬", "内敛", "奔放",
		"细腻", "粗犷", "精致", "豪放", "温润", "锐利", "柔和", "刚烈", "清新", "浓郁",
		"悠然", "率真", "洒脱", "慵懒", "倔强", "淡泊", "磊落", "爽朗", "憨厚", "腼腆",
		"果敢", "隐忍", "桀骜", "随性", "坦荡", "利落", "凌厉", "沧桑", "空灵", "通透",
		"跳脱", "笃定", "松弛", "清冷", "赤诚", "澄澈", "浑厚", "凛然", "飒爽", "蓬勃"}
	nouns := []string{"捕风者", "观星者", "远行者", "逐梦者", "程序员", "航海家", "筑梦者", "修行者", "开拓者", "探路者",
		"听风者", "赶路人", "追梦人", "夜行者", "晨光者", "月光者", "星光者", "阳光者",
		"风语者", "雨行者", "雪舞者", "花语者", "鸟语者", "鱼游者", "蝶舞者", "蜂鸣者",
		"设计师", "艺术家", "音乐家", "舞蹈家", "摄影师", "探险家", "科学家", "发明家",
		"思想家", "哲学家", "教育家", "牧羊人", "酿酒师", "铸剑师", "占星师", "养蜂人",
		"守塔人", "掌灯者", "拾荒者", "造梦师", "调香师", "炼金师", "织梦者", "寻路人",
		"摆渡人", "守夜人", "吹笛人", "弄潮儿", "独行侠", "流浪者", "驯马人", "炼丹师",
		"观潮者", "踏雪人", "御风者", "采药人", "望月者", "听雨人", "执笔者", "抚琴人",
		"弄墨客", "品茶人", "煮酒人", "读书人", "赏花人", "垂钓者", "放牧人", "种花人",
		"养鹤人", "驭剑者", "持灯人", "守林人"}

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

func parseDNSAddr(addr string) (host string, port int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		portStr = ""
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if host == "" {
		host = "127.0.0.1"
	}

	port = 5335
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		} else {
			port = 0
		}
	}

	return host, port
}

type DNSChat struct {
	group   []byte
	routeID []byte
	name    string
	sid     []byte
	key     []byte

	resolver *net.Resolver
	timeout  time.Duration
	verbose  bool
	onDebug  func(string)
}

func (dc *DNSChat) debug(format string, args ...interface{}) {
	if !dc.verbose {
		return
	}
	line := fmt.Sprintf("[DEBUG] "+format, args...)
	if dc.onDebug != nil {
		dc.onDebug(line)
		return
	}
	fmt.Println(line)
}

func NewDNSChat(dnsHost string, dnsPort int, group, name string, verbose bool) (*DNSChat, error) {
	sid, err := shared.RandomBytes(shared.SIDSize)
	if err != nil {
		return nil, err
	}
	serverAddr := net.JoinHostPort(dnsHost, strconv.Itoa(dnsPort))
	d := &net.Dialer{Timeout: 2 * time.Second}
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return d.DialContext(ctx, network, serverAddr)
	}}
	return &DNSChat{
		group:    []byte(group),
		routeID:  shared.RouteID([]byte(group)),
		name:     name,
		sid:      sid,
		key:      shared.DeriveKey([]byte(group)),
		resolver: r,
		timeout:  5 * time.Second,
		verbose:  verbose,
	}, nil
}

func buildQName(labels []string) string {
	s := strings.Join(labels, ".")
	return strings.TrimRight(s, ".") + "."
}

func (dc *DNSChat) headerLabels(dir, seqTotal string) ([]string, error) {
	queryNonce, err := shared.RandomBytes(shared.NonceSize)
	if err != nil {
		return nil, err
	}
	return []string{shared.B32Encode(dc.routeID), shared.B32Encode(dc.sid), dir, seqTotal, shared.B32Encode(queryNonce)}, nil
}

func (dc *DNSChat) queryTXT(qname string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dc.timeout)
	defer cancel()
	txts, err := dc.resolver.LookupTXT(ctx, qname)
	if err != nil {
		return nil, err
	}
	if len(txts) == 0 {
		return nil, fmt.Errorf("no answer")
	}
	return []byte(strings.Join(txts, "")), nil
}

var ErrNameTaken = fmt.Errorf("昵称已被占用")

func (dc *DNSChat) registerOnce() (bool, error) {
	header, err := dc.headerLabels(shared.DirJoin, "0")
	if err != nil {
		return false, err
	}
	labels := append(header, shared.SplitToLabels(shared.B32Encode([]byte(dc.name)), shared.LabelSegLen)...)
	resp, err := dc.queryTXT(buildQName(labels))
	if err != nil {
		return false, fmt.Errorf("注册失败: %w", err)
	}
	return string(resp) == shared.RespOK, nil
}

func (dc *DNSChat) RegisterName(autoRetry bool) (string, error) {
	maxAttempts := 1
	if autoRetry {
		maxAttempts = 10
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		ok, err := dc.registerOnce()
		if err != nil {
			return "", err
		}
		if ok {
			return dc.name, nil
		}
		if !autoRetry {
			return "", ErrNameTaken
		}
		dc.name = nickname()
	}
	return "", fmt.Errorf("昵称注册失败: 重试 %d 次仍有重名", maxAttempts)
}

func (dc *DNSChat) Leave() {
	header, err := dc.headerLabels(shared.DirLeave, "0")
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, _ = dc.resolver.LookupTXT(ctx, buildQName(header))
}

const (
	maxPayloadSize = 4096
	chunkSize      = 80
	chunkRetries   = 3
)

func (dc *DNSChat) SendMessage(message string) error {
	payload := append([]byte(dc.name), 0)
	payload = append(payload, []byte(message)...)
	if len(payload) > maxPayloadSize {
		return fmt.Errorf("消息过长: %d 字节, 上限 %d 字节", len(payload), maxPayloadSize)
	}

	msgNonce, err := shared.RandomBytes(shared.NonceSize)
	if err != nil {
		return fmt.Errorf("nonce 生成失败: %w", err)
	}
	e2eCt, err := shared.AESGCMEncrypt(dc.key, msgNonce, payload, dc.group)
	if err != nil {
		return fmt.Errorf("E2E 加密失败: %w", err)
	}
	data := append(msgNonce, e2eCt...)

	totalChunks := (len(data) + chunkSize - 1) / chunkSize
	dc.debug("[发送] 会话: %x; 消息: \"%s\"; E2E数据: %d字节; 分块数: %d;", dc.sid, message, len(data), totalChunks)
	var failed int
	reregisterAttempted := false

	for seq, i := 0, 0; i < len(data); seq, i = seq+1, i+chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		payloadLabels := shared.SplitToLabels(shared.B32Encode(data[i:end]), shared.LabelSegLen)

		var lastErr error
		var resp []byte
		for attempt := 0; attempt < chunkRetries; attempt++ {
			header, err := dc.headerLabels(shared.DirUpload, fmt.Sprintf("%d-%d", seq, totalChunks))
			if err != nil {
				lastErr = err
				continue
			}
			labels := append(header, payloadLabels...)
			resp, lastErr = dc.queryTXT(buildQName(labels))
			if lastErr == nil {
				break
			}
			dc.debug("[分块重试] seq: %d; 第%d次; 错误: %v;", seq, attempt+1, lastErr)
		}
		if lastErr != nil {
			dc.debug("[分块失败] seq: %d; 错误: %v;", seq, lastErr)
			failed++
		} else if string(resp) == shared.RespUnreg && !reregisterAttempted {
			reregisterAttempted = true
			dc.registerOnce()
		}
	}
	if failed > 0 {
		return fmt.Errorf("发送失败: %d/%d 分块未送达", failed, totalChunks)
	}
	return nil
}

func (dc *DNSChat) PollMessages() ([]string, bool) {
	header, err := dc.headerLabels(shared.DirPoll, "0")
	if err != nil {
		return nil, false
	}
	resp, err := dc.queryTXT(buildQName(header))
	if err != nil || len(resp) == 0 {
		return nil, false
	}
	data, err := shared.B64URLDecode(string(resp))
	if err != nil || len(data) == 0 {
		return nil, false
	}
	var messages []string
	for len(data) >= 2 {
		msgLen := int(data[0])<<8 | int(data[1])
		data = data[2:]
		if msgLen > len(data) {
			break
		}
		raw := data[:msgLen]
		data = data[msgLen:]
		if len(raw) < shared.MinE2EBlobLen {
			continue
		}
		msgNonce := raw[:shared.NonceSize]
		e2eCt := raw[shared.NonceSize:]
		plaintext, err := shared.AESGCMDecrypt(dc.key, msgNonce, e2eCt, dc.group)
		if err != nil {
			dc.debug("[E2E解密失败] 长度: %d; 错误: %v;", len(raw), err)
			continue
		}
		var formatted string
		if idx := bytes.IndexByte(plaintext, 0); idx >= 0 {
			formatted = fmt.Sprintf("%s: %s", string(plaintext[:idx]), string(plaintext[idx+1:]))
		} else {
			formatted = string(plaintext)
		}
		messages = append(messages, formatted)
	}
	if len(messages) == 0 {
		return nil, false
	}
	dc.debug("[接收] 会话: %x; 消息数: %d;", dc.sid, len(messages))
	return messages, true
}

func (dc *DNSChat) ReceiveLoop(baseInterval, maxInterval time.Duration, onMessage func(string), stop <-chan struct{}) {
	cur := baseInterval
	timer := time.NewTimer(cur)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			if msgs, ok := dc.PollMessages(); ok {
				for _, msg := range msgs {
					onMessage(msg)
				}
				cur = baseInterval
			} else {
				cur *= 2
				if cur > maxInterval {
					cur = maxInterval
				}
			}
			timer.Reset(cur)
		case <-stop:
			return
		}
	}
}

func wrapText(text string, maxW int, pad string) string {
	if maxW <= 0 {
		return text
	}
	var sb strings.Builder
	lineW := 0
	for _, r := range text {
		if r == '\n' {
			sb.WriteRune('\n')
			sb.WriteString(pad)
			lineW = 0
			continue
		}
		rw := runewidth.RuneWidth(r)
		if rw == 0 {
			rw = 1
		}
		if lineW+rw > maxW {
			sb.WriteRune('\n')
			sb.WriteString(pad)
			lineW = 0
		}
		sb.WriteRune(r)
		lineW += rw
	}
	return sb.String()
}

func drawSeparator(view *tview.TextView, w int, title string) {
	if w <= 0 {
		w = 80
	}
	if title == "" {
		fmt.Fprintf(view, "[%s]%s[-]\n", colorSep, strings.Repeat("─", w))
		return
	}
	label := " " + title + " "
	labelLen := len([]rune(label))
	left := (w - labelLen) / 2
	right := w - labelLen - left
	if left < 0 {
		left = 0
	}
	if right < 0 {
		right = 0
	}
	fmt.Fprintf(view, "[%s]%s[%s]%s[%s]%s[-]\n", colorSep, strings.Repeat("─", left), colorTitle, label, colorSep, strings.Repeat("─", right))
}

func main() {
	var name, group, dnsAddr, dnsHost string
	var dnsPort int
	var interval float64
	var verbose bool
	flag.StringVar(&name, "name", "", "昵称")
	flag.StringVar(&group, "group", "default", "分组ID")
	flag.StringVar(&dnsAddr, "dns", "127.0.0.1:5335", "DNS 服务器 (host:port 格式)")
	flag.Float64Var(&interval, "interval", 0.25, "轮询间隔(秒)")
	flag.BoolVar(&verbose, "verbose", false, "调试模式")
	flag.Parse()

	autoName := name == ""
	if autoName {
		name = nickname()
	}

	dnsHost, dnsPort = parseDNSAddr(dnsAddr)
	if dnsPort <= 0 || dnsPort > 65535 {
		fmt.Fprintf(os.Stderr, "无效 DNS 端口: %d\n", dnsPort)
		os.Exit(1)
	}
	if interval <= 0 {
		fmt.Fprintf(os.Stderr, "无效 interval: %.3f, 必须大于 0\n", interval)
		os.Exit(1)
	}

	cli, err := NewDNSChat(dnsHost, dnsPort, group, name, verbose)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	originalName := name
	registeredName, err := cli.RegisterName(autoName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	nameChanged := registeredName != originalName
	name = registeredName

	tview.Styles.PrimitiveBackgroundColor = tcell.ColorDefault

	app := tview.NewApplication()

	messageView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetChangedFunc(func() { app.Draw() })
	messageView.SetBorder(false)

	screen, _ := tcell.NewScreen()
	screenW := 80
	if screen != nil {
		if err := screen.Init(); err == nil {
			screenW, _ = screen.Size()
			screen.Fini()
		}
	}

	drawSeparator(messageView, screenW, "")
	fmt.Fprintf(messageView, "[%s] 连接: %s[-]\n", colorInfo, net.JoinHostPort(dnsHost, strconv.Itoa(dnsPort)))
	fmt.Fprintf(messageView, "[%s] 分组: %s[-]\n", colorInfo, group)
	drawSeparator(messageView, screenW, "")
	if nameChanged {
		fmt.Fprintf(messageView, "[%s] '%s' 已被占用, 已更名为 '%s'[-]\n", colorError, originalName, name)
	}
	fmt.Fprintln(messageView)

	inputArea := tview.NewTextArea().
		SetLabel("[" + colorSelf + "::b]> [-::-]").
		SetLabelWidth(3).
		SetWrap(true).
		SetTextStyle(tcell.StyleDefault.Background(tcell.ColorDefault).Foreground(tcell.NewHexColor(colorSelfTUI)).Bold(true))
	inputArea.SetBorder(false).SetBackgroundColor(tcell.ColorDefault)

	separator := tview.NewBox()
	separator.SetBorder(false).SetBackgroundColor(tcell.ColorDefault)
	separator.SetDrawFunc(func(screen tcell.Screen, x, y, w, h int) (int, int, int, int) {
		nameLabel := " " + name + " "
		nameLabelW := tview.TaggedStringWidth(nameLabel)
		rightW := 4
		leftW := w - nameLabelW - rightW
		if leftW < 0 {
			leftW = 0
		}
		line := "[" + colorSep + "]" + strings.Repeat("─", leftW) + "[" + colorSelf + "]" + nameLabel + "[" + colorSep + "]" + strings.Repeat("─", rightW) + "[-]"
		tview.Print(screen, line, x, y, w, tview.AlignLeft, tcell.ColorDefault)
		return x, y, w, h
	})

	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(messageView, 0, 1, false).
		AddItem(separator, 1, 0, false).
		AddItem(inputArea, 1, 0, true)

	const maxInputLines = 5
	inputHeight := 1
	computeInputLines := func(text string) int {
		w := screenW - 3
		if w < 1 {
			w = 1
		}
		lines, lineW := 1, 0
		for _, r := range text {
			if r == '\n' {
				lines++
				lineW = 0
				continue
			}
			rw := runewidth.RuneWidth(r)
			if rw == 0 {
				rw = 1
			}
			if lineW+rw > w {
				lines++
				lineW = rw
			} else {
				lineW += rw
			}
		}
		return lines
	}
	resizeInput := func(h int) {
		if h > maxInputLines {
			h = maxInputLines
		}
		if h < 1 {
			h = 1
		}
		if h == inputHeight {
			return
		}
		inputHeight = h
		flex.ResizeItem(inputArea, h, 0)
	}
	inputArea.SetMovedFunc(func() {
		resizeInput(computeInputLines(inputArea.GetText()))
	})

	var debugView *tview.TextView
	debugBrowsing := false
	if verbose {
		debugSep := tview.NewBox().SetBackgroundColor(tcell.ColorDefault)
		debugSep.SetDrawFunc(func(screen tcell.Screen, x, y, w, h int) (int, int, int, int) {
			label := " DEBUG "
			labelW := tview.TaggedStringWidth(label)
			leftW := w - labelW - 4
			if leftW < 0 {
				leftW = 0
			}
			line := "[" + colorSep + "]" + strings.Repeat("─", leftW) + "[" + colorTitle + "]" + label + "[" + colorSep + "]" + strings.Repeat("─", 4) + "[-]"
			tview.Print(screen, line, x, y, w, tview.AlignLeft, tcell.ColorDefault)
			return x, y, w, h
		})
		debugView = tview.NewTextView().
			SetDynamicColors(true).
			SetScrollable(true).
			SetChangedFunc(func() { app.Draw() })
		debugView.SetBorder(false).SetBackgroundColor(tcell.ColorDefault)
		flex.AddItem(debugSep, 1, 0, false).AddItem(debugView, 8, 0, false)
		cli.onDebug = func(line string) {
			app.QueueUpdateDraw(func() {
				fmt.Fprintf(debugView, "[%s]%s[-]\n", colorSep, line)
				if !debugBrowsing {
					debugView.ScrollToEnd()
				}
			})
		}
	}

	browsingHistory := false
	appendMessage := func(prefix, content string) {
		if prefix == "" {
			fmt.Fprintln(messageView, " "+content)
		} else {
			padW := tview.TaggedStringWidth(" " + prefix)
			pad := strings.Repeat(" ", padW)
			wrapped := wrapText(content, screenW-padW, pad)
			fmt.Fprintf(messageView, " %s%s\n", prefix, wrapped)
		}
		if !browsingHistory {
			messageView.ScrollToEnd()
		}
	}

	colorMap := map[string]string{}
	colorIdx := 0
	colorFor := func(sender string) string {
		if sender == name {
			return colorSelf
		}
		if c, ok := colorMap[sender]; ok {
			return c
		}
		c := peerColors[colorIdx%len(peerColors)]
		colorIdx++
		colorMap[sender] = c
		return c
	}

	var history []string
	histIdx := -1
	cursorMoved := false

	inputArea.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc || event.Key() == tcell.KeyCtrlC {
			app.Stop()
			return nil
		}
		if event.Key() == tcell.KeyCtrlJ {
			text := inputArea.GetText() + "\n"
			resizeInput(computeInputLines(text))
			go app.QueueUpdateDraw(func() {
				inputArea.SetText(text, true)
			})
			return nil
		}
		if event.Key() == tcell.KeyPgUp {
			if event.Modifiers()&tcell.ModAlt != 0 && debugView != nil {
				debugBrowsing = true
				row, col := debugView.GetScrollOffset()
				debugView.ScrollTo(row-5, col)
				return nil
			}
			browsingHistory = true
			row, col := messageView.GetScrollOffset()
			messageView.ScrollTo(row-5, col)
			return nil
		}
		if event.Key() == tcell.KeyPgDn {
			if event.Modifiers()&tcell.ModAlt != 0 && debugView != nil {
				row, col := debugView.GetScrollOffset()
				debugView.ScrollTo(row+5, col)
				_, _, _, h := debugView.GetInnerRect()
				if row+5 >= strings.Count(debugView.GetText(false), "\n")-h {
					debugBrowsing = false
					debugView.ScrollToEnd()
				}
				return nil
			}
			row, col := messageView.GetScrollOffset()
			messageView.ScrollTo(row+5, col)
			_, _, _, h := messageView.GetInnerRect()
			if row+5 >= strings.Count(messageView.GetText(false), "\n")-h {
				browsingHistory = false
				messageView.ScrollToEnd()
			}
			return nil
		}
		if event.Key() == tcell.KeyEnd {
			browsingHistory = false
			messageView.ScrollToEnd()
			if debugView != nil {
				debugBrowsing = false
				debugView.ScrollToEnd()
			}
			return nil
		}
		if event.Key() == tcell.KeyEnter {
			text := strings.TrimSpace(inputArea.GetText())
			if text == "" {
				return nil
			}
			history = append(history, text)
			histIdx = -1
			cursorMoved = false
			inputArea.SetText("", true)
			appendMessage(fmt.Sprintf("[%s]%s[-]: ", colorFor(name), name), text)
			go func() {
				if err := cli.SendMessage(text); err != nil {
					app.QueueUpdateDraw(func() {
						appendMessage("", fmt.Sprintf("[%s]%v[-]", colorError, err))
					})
				}
			}()
			return nil
		}
		if event.Key() == tcell.KeyLeft || event.Key() == tcell.KeyRight {
			cursorMoved = true
			return event
		}
		if (event.Key() == tcell.KeyUp || event.Key() == tcell.KeyDown) && cursorMoved {
			return event
		}
		if event.Key() == tcell.KeyUp && len(history) > 0 {
			if histIdx == -1 {
				histIdx = len(history) - 1
			} else if histIdx > 0 {
				histIdx--
			}
			inputArea.SetText(history[histIdx], true)
			cursorMoved = false
			return nil
		}
		if event.Key() == tcell.KeyDown && len(history) > 0 {
			if histIdx >= 0 && histIdx < len(history)-1 {
				histIdx++
				inputArea.SetText(history[histIdx], true)
			} else {
				histIdx = -1
				inputArea.SetText("", true)
			}
			cursorMoved = false
			return nil
		}
		return event
	})

	stop := make(chan struct{})
	baseInterval := time.Duration(interval*1000) * time.Millisecond
	maxInterval := 2 * time.Second
	go cli.ReceiveLoop(baseInterval, maxInterval, func(msg string) {
		app.QueueUpdateDraw(func() {
			if idx := strings.Index(msg, ": "); idx >= 0 {
				sender := msg[:idx]
				content := msg[idx+2:]
				appendMessage(fmt.Sprintf("[%s]%s[-]: ", colorFor(sender), sender), content)
			} else {
				appendMessage("", msg)
			}
		})
	}, stop)

	app.SetRoot(flex, true).EnableMouse(false)
	if err := app.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	close(stop)
	cli.Leave()
}
