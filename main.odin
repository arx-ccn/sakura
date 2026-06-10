package sakura

import "core:fmt"
import "core:mem/virtual"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:thread"
import "core:time"

g_listen: net.TCP_Socket

unix_now :: proc() -> i64 {
	return time.time_to_unix(time.now())
}

@(private = "file")
env_or :: proc(key, def: string) -> string {
	v := os.get_env(key, context.allocator)
	if v == "" {
		return def
	}
	return v
}

@(private = "file")
env_int :: proc(key: string, def: int) -> int {
	v := os.get_env(key, context.allocator)
	if v == "" {
		return def
	}
	n, ok := strconv.parse_int(v)
	if !ok {
		return def
	}
	return n
}

main :: proc() {
	// Self-test mode: verify the crypto against known vectors and exit.
	for arg in os.args[1:] {
		if arg == "--selftest" {
			os.exit(run_selftest() ? 0 : 1)
		}
		if arg == "--help" {
			print_help()
			os.exit(0)
		}
	}
	// --sha256 <file>  (differential testing against the system sha256sum)
	if len(os.args) >= 3 && os.args[1] == "--sha256" {
		data, rerr := os.read_entire_file_from_path(os.args[2], context.allocator)
		if rerr != nil {
			fmt.eprintln("cannot read", os.args[2])
			os.exit(1)
		}
		d := sha256(data)
		fmt.println(hex_string(d[:]))
		os.exit(0)
	}
	// --pubkey <seckey_hex>
	if len(os.args) >= 3 && os.args[1] == "--pubkey" {
		sk: [32]u8
		if !hex_decode(sk[:], os.args[2]) {
			fmt.eprintln("bad secret key")
			os.exit(1)
		}
		pk, ok := schnorr_pubkey(sk[:])
		if !ok {
			fmt.eprintln("invalid secret key")
			os.exit(1)
		}
		fmt.println(hex_string(pk[:]))
		os.exit(0)
	}
	// --make-token <seckey_hex> <verb> [hash] [exp_unix]
	if len(os.args) >= 4 && os.args[1] == "--make-token" {
		seckey := os.args[2]
		verb := os.args[3]
		hash := len(os.args) >= 5 ? os.args[4] : ""
		exp := unix_now() + 3600
		if len(os.args) >= 6 {
			if v, ok := strconv.parse_i64(os.args[5]); ok {
				exp = v
			}
		}
		token, ok := mint_token(seckey, verb, hash, exp, unix_now())
		if !ok {
			fmt.eprintln("failed to mint token")
			os.exit(1)
		}
		fmt.println(token)
		os.exit(0)
	}

	cfg := Config {
		host         = env_or("SAKURA_HOST", "0.0.0.0"),
		port         = env_int("SAKURA_PORT", 3000),
		data_dir     = env_or("SAKURA_DATA", "./data"),
		domain       = env_or("SAKURA_DOMAIN", ""),
		public_url   = env_or("SAKURA_PUBLIC_URL", ""),
		max_body     = env_int("SAKURA_MAX_MB", 100) * 1024 * 1024,
		workers      = env_int("SAKURA_WORKERS", 0),
		require_auth = env_or("SAKURA_REQUIRE_AUTH", "true") != "false",
	}
	if cfg.workers <= 0 {
		cfg.workers = 16
	}
	g_config = &cfg

	store: Store
	if !store_init(&store, cfg.data_dir) {
		fmt.eprintln("fatal: could not initialise store at", cfg.data_dir)
		os.exit(1)
	}
	g_store = &store

	// Bind the listening socket.
	addr: net.Address
	if cfg.host == "" || cfg.host == "0.0.0.0" {
		addr = net.IP4_Any
	} else {
		parsed := net.parse_address(cfg.host)
		if parsed == nil {
			addr = net.IP4_Any
		} else {
			addr = parsed
		}
	}
	ep := net.Endpoint{address = addr, port = cfg.port}
	sock, lerr := net.listen_tcp(ep)
	if lerr != nil {
		fmt.eprintln("fatal: could not listen on", cfg.host, cfg.port, "-", lerr)
		os.exit(1)
	}
	g_listen = sock

	fmt.printfln(
		"sakura blossom server listening on %s:%d  (data=%s, workers=%d, max=%dMB, auth=%v)",
		cfg.host, cfg.port, cfg.data_dir, cfg.workers, cfg.max_body / (1024 * 1024), cfg.require_auth,
	)

	// Spawn worker threads; the main thread joins as a worker too.
	for _ in 0 ..< cfg.workers - 1 {
		t := thread.create(worker_proc)
		thread.start(t)
	}
	worker_proc(nil)
}

@(private = "file")
worker_proc :: proc(t: ^thread.Thread) {
	arena: virtual.Arena
	if virtual.arena_init_growing(&arena) != nil {
		return
	}
	for {
		client, _, err := net.accept_tcp(g_listen)
		if err != nil {
			continue
		}
		// Idle keep-alive clients must not pin a worker forever: a receive
		// timeout bounds how long any single recv blocks. recv() returning a
		// timeout error then closes the connection in read_request/body reads.
		net.set_option(client, .Receive_Timeout, 30 * time.Second)
		handle_conn(client, &arena)
	}
}

@(private = "file")
handle_conn :: proc(sock: net.TCP_Socket, arena: ^virtual.Arena) {
	conn: Conn
	conn.sock = sock
	conn.buf = make([dynamic]u8) // connection-lifetime buffer (heap)
	defer {
		delete(conn.buf)
		net.close(sock)
	}

	base := context
	for {
		virtual.arena_free_all(arena)
		ctx := base
		ctx.allocator = virtual.arena_allocator(arena)
		ctx.temp_allocator = virtual.arena_allocator(arena)
		context = ctx

		req, ok := read_request(&conn, g_config.max_body)
		if !ok {
			break
		}
		alive := req.keep_alive
		if !handle_request(&req, &conn) {
			break
		}
		conn_compact(&conn)
		if !alive {
			break
		}
	}
}

@(private = "file")
print_help :: proc() {
	fmt.println("sakura — a dependency-free Blossom server (Odin)")
	fmt.println("")
	fmt.println("Usage: sakura [--selftest] [--help]")
	fmt.println("")
	fmt.println("Configuration via environment variables:")
	fmt.println("  SAKURA_HOST          bind address (default 0.0.0.0)")
	fmt.println("  SAKURA_PORT          listen port (default 3000)")
	fmt.println("  SAKURA_DATA          data directory (default ./data)")
	fmt.println("  SAKURA_DOMAIN        domain for BUD-11 server-tag scoping (default off)")
	fmt.println("  SAKURA_PUBLIC_URL    base URL for blob descriptors (default derives from Host)")
	fmt.println("  SAKURA_MAX_MB        max blob size in MB (default 100)")
	fmt.println("  SAKURA_WORKERS       worker threads (default 16)")
	fmt.println("  SAKURA_REQUIRE_AUTH  require auth for upload/delete/mirror (default true)")
}

// --- self-test: SHA-256 KATs, secp unit tests, full BIP-340 vectors -------

@(private = "file")
unhex :: proc(s: string) -> []u8 {
	b := make([]u8, len(s) / 2)
	hex_decode(b, s)
	return b
}

@(private = "file")
run_selftest :: proc() -> bool {
	pass := 0
	fail := 0
	tally :: proc(name: string, ok: bool, pass, fail: ^int) {
		if ok {pass^ += 1} else {fail^ += 1}
		fmt.printfln("  [%s] %s", ok ? "PASS" : "FAIL", name)
	}

	// ---- SHA-256 known-answer tests (NIST / canonical) ----
	fmt.println("== SHA-256 known-answer vectors ==")
	Sha_Kat :: struct {
		input: string,
		want:  string,
	}
	sha_kats := []Sha_Kat{
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
		},
		{
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			"cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
		},
	}
	for k in sha_kats {
		d := sha256(transmute([]u8)k.input)
		label := len(k.input) <= 12 ? fmt.tprintf("sha256(%q)", k.input) : fmt.tprintf("sha256(%d bytes)", len(k.input))
		tally(label, hex_string(d[:]) == k.want, &pass, &fail)
	}
	// One-million 'a' (classic streaming/padding stress).
	{
		million := make([]u8, 1_000_000)
		for i in 0 ..< len(million) {million[i] = 'a'}
		d := sha256(million)
		want := "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
		tally("sha256(1,000,000 x 'a')", hex_string(d[:]) == want, &pass, &fail)
		delete(million)
	}

	// ---- secp256k1 field/scalar/point unit tests ----
	fmt.println("== secp256k1 arithmetic units ==")
	sp, sf := secp_unit_tests()
	pass += sp
	fail += sf

	// ---- BIP-340 verification vectors (all 19 from the spec CSV) ----
	fmt.println("== BIP-340 verification vectors ==")
	Vec :: struct {
		pubkey: string,
		msg:    string,
		sig:    string,
		expect: bool,
		note:   string,
	}
	vectors := []Vec {
		{"F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", "0000000000000000000000000000000000000000000000000000000000000000", "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0", true, ""},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A", true, ""},
		{"DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8", "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C", "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7", true, ""},
		{"25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3", true, "msg not reduced mod p/n"},
		{"D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9", "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703", "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4", true, ""},
		{"EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false, "pubkey not on curve"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2", false, "has_even_y(R) false"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD", false, "negated message"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6", false, "negated s"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051", false, "sG-eP infinite (R.x=0)"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197", false, "sG-eP infinite (R.x=1)"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false, "sig[0:32] not on curve"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false, "sig[0:32] == field size"},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", false, "sig[32:64] == curve order"},
		{"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false, "pubkey exceeds field size"},
		{"778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "", "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63", true, "message size 0"},
		{"778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "11", "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF", true, "message size 1"},
		{"778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "0102030405060708090A0B0C0D0E0F1011", "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5", true, "message size 17"},
		{"778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999", "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367", true, "message size 100"},
	}
	for v, i in vectors {
		got := schnorr_verify(unhex(v.pubkey), unhex(v.msg), unhex(v.sig))
		label := v.note == "" ? fmt.tprintf("vector %d (expect %v)", i, v.expect) : fmt.tprintf("vector %d (%s)", i, v.note)
		tally(label, got == v.expect, &pass, &fail)
	}

	// ---- BIP-340 signing vectors (only aux_rand == 0, which our signer uses) ----
	fmt.println("== BIP-340 signing vectors (aux=0) ==")
	Sign_Vec :: struct {
		seckey:  string,
		pubkey:  string,
		msg:     string,
		sig:     string,
	}
	sign_vectors := []Sign_Vec {
		{"0000000000000000000000000000000000000000000000000000000000000003", "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", "0000000000000000000000000000000000000000000000000000000000000000", "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"},
		{"0340034003400340034003400340034003400340034003400340034003400340", "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "", "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63"},
		{"0340034003400340034003400340034003400340034003400340034003400340", "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "11", "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF"},
		{"0340034003400340034003400340034003400340034003400340034003400340", "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "0102030405060708090A0B0C0D0E0F1011", "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5"},
		{"0340034003400340034003400340034003400340034003400340034003400340", "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999", "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367"},
	}
	for v, i in sign_vectors {
		sk := unhex(v.seckey)
		// pubkey derivation
		pk, pok := schnorr_pubkey(sk)
		tally(fmt.tprintf("sign vector %d pubkey", i), pok && hex_string(pk[:]) == ascii_lower_str(v.pubkey), &pass, &fail)
		// signature must be byte-exact (deterministic with aux=0)
		sig, sok := schnorr_sign(sk, unhex(v.msg))
		tally(fmt.tprintf("sign vector %d signature", i), sok && hex_string(sig[:]) == ascii_lower_str(v.sig), &pass, &fail)
	}

	fmt.printfln("\n%d passed, %d failed", pass, fail)
	if fail == 0 {
		fmt.println("ALL TESTS PASSED")
	} else {
		fmt.println("SOME TESTS FAILED")
	}
	return fail == 0
}

@(private = "file")
ascii_lower_str :: proc(s: string) -> string {
	buf := make([]u8, len(s))
	for i in 0 ..< len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {c += 32}
		buf[i] = c
	}
	return string(buf)
}
