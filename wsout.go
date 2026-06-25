// Package wsoutext provides the transport.ws.outbound capability for Pulp
// cells: dialing an outbound WebSocket. The cell is sandboxed WASM and cannot
// open sockets, so the host dials on its behalf — github.com/gorilla/websocket
// here. The cell dials a URL (wsout_dial), sends frames (wsout_send), and the
// host streams inbound frames back as `wsout.frame` step events (Poll). The
// cell bridges those to a browser's inbound WebSocket — this is the remote
// terminal relay: browser WS <-> cell <-> remote machine WS.
//
// Deployment:
//
//	import _ "github.com/BananaLabs-OSS/Pulp-ext-wsout"
//
// Host imports:
//
//	wsout_dial(req_ptr, req_len, resp_ptr_out, resp_len_out) -> code   # req{url, headers}; resp{conn_id}
//	wsout_send(conn_id, data_ptr, data_len) -> code
//	wsout_close(conn_id) -> code
package wsoutext

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/gorilla/websocket"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/vmihailenco/msgpack/v5"
)

// Optional egress allowlist for outbound WS (mirrors PROCESS_ALLOW_BINS). Parsed
// from WSOUT_ALLOW (comma-separated hosts or CIDRs) at Setup. EMPTY = allow all
// (the default — a single-user relay must reach localhost/LAN); set it to lock down.
// Loopback is always permitted (the desktop/forward helpers dial 127.0.0.1).
var (
	wsAllowHosts = map[string]struct{}{}
	wsAllowNets  []*net.IPNet
	wsAllowOn    bool
)

func parseWSAllow(s string) {
	for _, raw := range strings.Split(s, ",") {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		wsAllowOn = true
		if _, ipnet, err := net.ParseCIDR(e); err == nil {
			wsAllowNets = append(wsAllowNets, ipnet)
			continue
		}
		wsAllowHosts[strings.ToLower(e)] = struct{}{}
	}
}

// wsAllowed reports whether dialing rawURL is permitted by the allowlist.
func wsAllowed(rawURL string) bool {
	if !wsAllowOn {
		return true // no allowlist configured → permissive (single-user default)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "127.0.0.1" || host == "::1" || host == "localhost" {
		return true
	}
	if _, ok := wsAllowHosts[host]; ok {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return true
		}
		for _, n := range wsAllowNets {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

const (
	codeOK          = 0
	codeBadReq      = 1
	codeMemRead     = 2
	codeDecode      = 3
	codeDialFailed  = 4
	codeSendFailed  = 5
	codeNoSession   = 6
	codeAllocFailed = 7
	codeMemWrite    = 8
	codeCapAbsent   = 99
	// 32 MiB of un-drained inbound frames per conn before the oldest are dropped.
	// Must exceed the largest single coherent burst the relay carries — a multi-monitor
	// ZRLE desktop frame is several MB; at 1 MiB it was truncated mid-stream, desyncing
	// the RFB byte stream (garbage header). The step loop drains continuously, so this
	// is only a burst ceiling, not steady-state memory.
	maxBufferPerConn = 32 << 20
)

type session struct {
	id     uint32
	cellID string
	conn   *websocket.Conn

	mu     sync.Mutex
	buf    []byte // buffered inbound payloads awaiting Poll
	closed bool
}

var (
	mu       sync.Mutex
	sessions = map[uint32]*session{}
	order    []uint32 // round-robin Poll fairness
	nextID   uint32
	nextEvID uint64
	logger   = slog.Default()
)

func init() {
	ext.Register(ext.Capability{
		Name:         "transport.ws.outbound",
		Setup:        setup,
		Teardown:     teardown,
		TeardownCell: teardownCell,
		Register:     bindActive,
		Stub:         bindStub,
		Poll:         pollFrames,
		// Finalize is a no-op: frames are drained into the event at Poll time.
	})
}

func setup(env ext.SetupEnv) error {
	if env.Logger != nil {
		logger = env.Logger
	}
	parseWSAllow(os.Getenv("WSOUT_ALLOW"))
	logger.Info("transport.ws.outbound ready", "egress_allowlist", wsAllowOn)
	return nil
}

func teardown(_ context.Context) error {
	mu.Lock()
	defer mu.Unlock()
	for id, s := range sessions {
		_ = s.conn.Close()
		delete(sessions, id)
	}
	order = nil
	return nil
}

// teardownCell closes ONLY the named cell's outbound WS connections on `ctl reload`.
// Without this, a self-rebuild leaves the old cell's relay/HMR sockets + their reader
// goroutines alive for the host's lifetime, accumulating across rebuilds.
func teardownCell(_ context.Context, cellID string) error {
	mu.Lock()
	defer mu.Unlock()
	for id, s := range sessions {
		if s != nil && s.cellID == cellID {
			_ = s.conn.Close()
			delete(sessions, id)
		}
	}
	kept := order[:0] // prune order to surviving sessions
	for _, id := range order {
		if _, ok := sessions[id]; ok {
			kept = append(kept, id)
		}
	}
	order = kept
	return nil
}

// ---- binding ---------------------------------------------------------------

func bindActive(b wazero.HostModuleBuilder, cell ext.Cell) error {
	cellID := ""
	if cell != nil {
		cellID = cell.Name()
	}
	b.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
		return wsoutDial(ctx, m, cellID, reqPtr, reqLen, respPtrOut, respLenOut)
	}).Export("wsout_dial")
	b.NewFunctionBuilder().WithFunc(func(_ context.Context, m api.Module, id, dataPtr, dataLen uint32) uint32 {
		return wsoutSend(m, id, dataPtr, dataLen)
	}).Export("wsout_send")
	b.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module, id uint32) uint32 {
		return wsoutClose(id)
	}).Export("wsout_close")
	return nil
}

func bindStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	b.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module, _, _, _, _ uint32) uint32 { return codeCapAbsent }).Export("wsout_dial")
	b.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module, _, _, _ uint32) uint32 { return codeCapAbsent }).Export("wsout_send")
	b.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module, _ uint32) uint32 { return codeCapAbsent }).Export("wsout_close")
	return nil
}

// ---- handlers --------------------------------------------------------------

func wsoutDial(ctx context.Context, m api.Module, cellID string, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
	var req struct {
		URL     string            `msgpack:"url"`
		Headers map[string]string `msgpack:"headers"`
	}
	if reqLen == 0 {
		return codeBadReq
	}
	data, ok := m.Memory().Read(reqPtr, reqLen)
	if !ok {
		return codeMemRead
	}
	if err := msgpack.Unmarshal(data, &req); err != nil {
		return codeDecode
	}
	if req.URL == "" {
		return codeBadReq
	}
	if !wsAllowed(req.URL) {
		logger.Warn("transport.ws.outbound: blocked by WSOUT_ALLOW", "cell", cellID, "url", req.URL)
		return codeBadReq
	}

	var hdr http.Header
	if len(req.Headers) > 0 {
		hdr = http.Header{}
		for k, v := range req.Headers {
			hdr.Set(k, v)
		}
	}
	conn, _, err := websocket.DefaultDialer.Dial(req.URL, hdr)
	if err != nil {
		logger.Error("wsout dial", "url", req.URL, "err", err)
		return codeDialFailed
	}

	mu.Lock()
	nextID++
	id := nextID
	s := &session{id: id, cellID: cellID, conn: conn}
	sessions[id] = s
	order = append(order, id)
	mu.Unlock()

	go readLoop(s)

	resp, _ := msgpack.Marshal(struct {
		ConnID uint32 `msgpack:"conn_id"`
	}{ConnID: id})
	return writeResp(ctx, m, resp, respPtrOut, respLenOut)
}

// readLoop pumps inbound WS frames into the session buffer until close/error.
func readLoop(s *session) {
	for {
		_, payload, err := s.conn.ReadMessage()
		if len(payload) > 0 {
			s.mu.Lock()
			s.buf = append(s.buf, payload...)
			if len(s.buf) > maxBufferPerConn {
				s.buf = s.buf[len(s.buf)-maxBufferPerConn:]
			}
			s.mu.Unlock()
		}
		if err != nil {
			s.mu.Lock()
			s.closed = true
			s.mu.Unlock()
			return
		}
	}
}

func wsoutSend(m api.Module, id, dataPtr, dataLen uint32) uint32 {
	s := getSession(id)
	if s == nil {
		return codeNoSession
	}
	data, ok := m.Memory().Read(dataPtr, dataLen)
	if !ok {
		return codeMemRead
	}
	if err := s.conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return codeSendFailed
	}
	return codeOK
}

func wsoutClose(id uint32) uint32 {
	mu.Lock()
	s := sessions[id]
	delete(sessions, id)
	for i, x := range order {
		if x == id {
			order = append(order[:i], order[i+1:]...)
			break
		}
	}
	mu.Unlock()
	if s == nil {
		return codeNoSession
	}
	_ = s.conn.Close()
	return codeOK
}

func getSession(id uint32) *session {
	mu.Lock()
	defer mu.Unlock()
	return sessions[id]
}

// pollFrames drains one session's buffered inbound frames per call (round-robin)
// and emits them as a wsout.frame event for that session's cell. Returns
// ok=false when nothing is pending.
func pollFrames() (ext.StepEvent, bool) {
	mu.Lock()
	ids := append([]uint32(nil), order...)
	mu.Unlock()
	for _, id := range ids {
		s := getSession(id)
		if s == nil {
			continue
		}
		s.mu.Lock()
		if len(s.buf) == 0 {
			s.mu.Unlock()
			continue
		}
		data := s.buf
		s.buf = nil
		s.mu.Unlock()

		payload, err := msgpack.Marshal(struct {
			ConnID uint32 `msgpack:"conn_id"`
			Data   []byte `msgpack:"data"`
		}{ConnID: id, Data: data})
		if err != nil {
			continue
		}
		mu.Lock()
		nextEvID++
		evID := nextEvID
		// rotate this id to the back for fairness
		for i, x := range order {
			if x == id {
				order = append(append(order[:i:i], order[i+1:]...), id)
				break
			}
		}
		mu.Unlock()
		return ext.StepEvent{Kind: "wsout.frame", Payload: payload, ID: evID, CellID: s.cellID}, true
	}
	return ext.StepEvent{}, false
}

func writeResp(ctx context.Context, m api.Module, data []byte, respPtrOut, respLenOut uint32) uint32 {
	allocFn := m.ExportedFunction("pulp_alloc")
	if allocFn == nil {
		return codeAllocFailed
	}
	res, err := allocFn.Call(ctx, uint64(len(data)))
	if err != nil || len(res) == 0 {
		return codeAllocFailed
	}
	ptr := uint32(res[0])
	if ptr == 0 || !m.Memory().Write(ptr, data) {
		return codeMemWrite
	}
	if !m.Memory().WriteUint32Le(respPtrOut, ptr) || !m.Memory().WriteUint32Le(respLenOut, uint32(len(data))) {
		return codeMemWrite
	}
	return codeOK
}
