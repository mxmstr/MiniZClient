package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	configVersion = 1

	hkeyClassesRoot = syscall.Handle(0x80000000)
	hkeyCurrentUser = syscall.Handle(0x80000001)

	keyRead  = 0x20019
	keyWrite = 0x20006
	regSZ    = 1

	errorSuccess      = 0
	errorFileNotFound = 2

	userProtocolKey = `Software\Classes\zlo`
	commandSubkey   = `shell\open\command`
	shimMarker      = `ZloUriShim`
)

var (
	advapi32          = syscall.NewLazyDLL("advapi32.dll")
	regOpenKeyExW     = advapi32.NewProc("RegOpenKeyExW")
	regCreateKeyExW   = advapi32.NewProc("RegCreateKeyExW")
	regQueryValueExW  = advapi32.NewProc("RegQueryValueExW")
	regSetValueExW    = advapi32.NewProc("RegSetValueExW")
	regDeleteTreeW    = advapi32.NewProc("RegDeleteTreeW")
	regCloseKey       = advapi32.NewProc("RegCloseKey")
	shell32           = syscall.NewLazyDLL("shell32.dll")
	commandLineToArgv = shell32.NewProc("CommandLineToArgvW")
	shChangeNotify    = shell32.NewProc("SHChangeNotify")
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	localFree         = kernel32.NewProc("LocalFree")
)

type config struct {
	Version         int      `json:"version"`
	ShimPath        string   `json:"shim_path"`
	OriginalCommand string   `json:"original_command"`
	OriginalArgv    []string `json:"original_argv"`
	CaptureLog      string   `json:"capture_log"`
	InstalledAt     string   `json:"installed_at"`
}

type captureRecord struct {
	Timestamp string   `json:"timestamp"`
	PID       int      `json:"pid"`
	URI       string   `json:"uri,omitempty"`
	Payload   string   `json:"payload,omitempty"`
	LaunchURL string   `json:"launch_url,omitempty"`
	Mode      string   `json:"mode,omitempty"`
	GameID    string   `json:"game_id,omitempty"`
	Source    string   `json:"source,omitempty"`
	Argv      []string `json:"argv,omitempty"`
	Event     string   `json:"event,omitempty"`
	Error     string   `json:"error,omitempty"`
}

var battlelogLaunchPattern = regexp.MustCompile(`http://(?:localhost|127\.0\.0\.1):5080/ZLO/run\?[A-Za-z0-9%+&=._~-]+`)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ZloUriShim:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}

	switch strings.ToLower(args[0]) {
	case "install":
		return installCommand(args[1:])
	case "uninstall":
		return uninstallCommand(args[1:])
	case "status":
		return statusCommand(args[1:])
	case "replay":
		return replayCommand(args[1:])
	case "discover":
		return discoverCommand(args[1:])
	case "launch":
		return launchCommand(args[1:])
	default:
		if !strings.HasPrefix(strings.ToLower(args[0]), "zlo://") {
			return usageError()
		}
		return captureAndForward(args[0])
	}
}

func usageError() error {
	return errors.New("usage: ZloUriShim.exe install [--target ZClient.exe] | uninstall | status | discover | launch --mode sp|mp [--game-id ID] | launch --url URL | replay --last | zlo://...")
}

func installCommand(args []string) error {
	set := flag.NewFlagSet("install", flag.ContinueOnError)
	target := set.String("target", "", "path to the real ZClient.exe")
	logPath := set.String("log", "", "capture JSONL path")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return usageError()
	}

	shimPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate shim executable: %w", err)
	}
	shimPath, err = filepath.Abs(shimPath)
	if err != nil {
		return fmt.Errorf("resolve shim executable: %w", err)
	}

	paths, err := statePaths()
	if err != nil {
		return err
	}
	if *logPath == "" {
		*logPath = paths.captureLog
	} else if *logPath, err = filepath.Abs(*logPath); err != nil {
		return fmt.Errorf("resolve capture log: %w", err)
	}

	if marker, markerErr := queryString(hkeyCurrentUser, userProtocolKey, shimMarker); markerErr == nil {
		if samePath(marker, shimPath) {
			return fmt.Errorf("already installed; run %q status", shimPath)
		}
		return fmt.Errorf("a different ZloUriShim owns the per-user zlo protocol: %s", marker)
	} else if !errors.Is(markerErr, os.ErrNotExist) {
		return fmt.Errorf("inspect existing per-user protocol: %w", markerErr)
	}
	if exists, err := keyExists(hkeyCurrentUser, userProtocolKey); err != nil {
		return fmt.Errorf("inspect existing per-user protocol: %w", err)
	} else if exists {
		return errors.New(`HKCU\Software\Classes\zlo already exists; refusing to overwrite a user protocol registration`)
	}

	var originalCommand string
	var originalArgv []string
	if *target != "" {
		targetPath, absErr := filepath.Abs(*target)
		if absErr != nil {
			return fmt.Errorf("resolve target: %w", absErr)
		}
		if info, statErr := os.Stat(targetPath); statErr != nil || info.IsDir() {
			if statErr == nil {
				statErr = errors.New("target is a directory")
			}
			return fmt.Errorf("invalid target %q: %w", targetPath, statErr)
		}
		originalArgv = []string{targetPath, "%1"}
		originalCommand = quoteWindowsArg(targetPath) + ` "%1"`
	} else {
		originalCommand, err = queryString(hkeyClassesRoot, `zlo\shell\open\command`, "")
		if err != nil {
			return fmt.Errorf("read the current effective zlo handler (or use --target): %w", err)
		}
		originalArgv, err = splitWindowsCommandLine(originalCommand)
		if err != nil {
			return fmt.Errorf("parse current zlo handler: %w", err)
		}
	}
	if len(originalArgv) == 0 || samePath(originalArgv[0], shimPath) {
		return errors.New("the effective zlo handler resolves to this shim; use install --target with the real ZClient.exe")
	}

	if err := os.MkdirAll(paths.dir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	cfg := config{
		Version:         configVersion,
		ShimPath:        shimPath,
		OriginalCommand: originalCommand,
		OriginalArgv:    originalArgv,
		CaptureLog:      *logPath,
		InstalledAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := saveConfig(paths.config, cfg); err != nil {
		return err
	}
	if err := registerProtocol(shimPath); err != nil {
		_ = os.Remove(paths.config)
		return err
	}
	notifyAssociationChanged()
	fmt.Printf("Installed per-user zlo:// shim\nReal handler: %s\nCapture log: %s\n", originalCommand, cfg.CaptureLog)
	return nil
}

func uninstallCommand(args []string) error {
	if len(args) != 0 {
		return usageError()
	}
	shimPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate shim executable: %w", err)
	}
	marker, err := queryString(hkeyCurrentUser, userProtocolKey, shimMarker)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("the per-user zlo:// shim is not installed")
	}
	if err != nil {
		return fmt.Errorf("read shim marker: %w", err)
	}
	if !samePath(marker, shimPath) {
		return fmt.Errorf("refusing to remove a protocol owned by %s", marker)
	}
	if err := deleteTree(hkeyCurrentUser, userProtocolKey); err != nil {
		return fmt.Errorf("remove per-user protocol: %w", err)
	}
	notifyAssociationChanged()
	fmt.Println("Removed the per-user shim; Windows will use the original machine-wide zlo:// handler again.")
	return nil
}

func statusCommand(args []string) error {
	if len(args) != 0 {
		return usageError()
	}
	paths, err := statePaths()
	if err != nil {
		return err
	}
	cfg, cfgErr := loadConfig(paths.config)
	marker, markerErr := queryString(hkeyCurrentUser, userProtocolKey, shimMarker)
	command, commandErr := queryString(hkeyClassesRoot, `zlo\shell\open\command`, "")
	fmt.Printf("Config: %s\n", paths.config)
	if cfgErr == nil {
		fmt.Printf("Original handler: %s\nCapture log: %s\n", cfg.OriginalCommand, cfg.CaptureLog)
	} else {
		fmt.Printf("Config state: %v\n", cfgErr)
	}
	if markerErr == nil {
		fmt.Printf("Installed shim: %s\n", marker)
	} else {
		fmt.Println("Installed shim: no")
	}
	if commandErr == nil {
		fmt.Printf("Effective handler: %s\n", command)
	}
	return nil
}

func replayCommand(args []string) error {
	set := flag.NewFlagSet("replay", flag.ContinueOnError)
	last := set.Bool("last", false, "replay the most recent capture")
	if err := set.Parse(args); err != nil {
		return err
	}
	cfg, _, err := currentConfig()
	if err != nil {
		return err
	}
	var launch string
	if *last {
		if set.NArg() != 0 {
			return usageError()
		}
		launch, err = lastCapturedLaunch(cfg.CaptureLog)
		if err != nil {
			return err
		}
	} else {
		if set.NArg() != 1 {
			return usageError()
		}
		launch = set.Arg(0)
	}
	if strings.HasPrefix(strings.ToLower(launch), "zlo://") {
		return forward(cfg, launch)
	}
	return requestLaunchURL(launch)
}

func discoverCommand(args []string) error {
	set := flag.NewFlagSet("discover", flag.ContinueOnError)
	cachePath := set.String("cache", "", "specific browser cache directory or file")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return usageError()
	}
	cfg, _, err := currentConfig()
	if err != nil {
		return err
	}
	sources, err := browserCacheSources(*cachePath)
	if err != nil {
		return err
	}
	existing, err := capturedLaunchSet(cfg.CaptureLog)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	type foundLaunch struct {
		url    string
		source string
	}
	found := make(map[string]foundLaunch)
	for _, source := range sources {
		info, statErr := os.Stat(source)
		if statErr != nil || info.IsDir() || info.Size() > 64*1024*1024 {
			continue
		}
		data, readErr := readSharedFile(source, 64*1024*1024)
		if readErr != nil {
			continue
		}
		for _, match := range battlelogLaunchPattern.FindAll(data, -1) {
			value := string(match)
			found[value] = foundLaunch{url: value, source: source}
		}
	}
	if len(found) == 0 {
		return errors.New("no Battlefield launch URLs found in the browser cache")
	}
	urls := make([]string, 0, len(found))
	for value := range found {
		urls = append(urls, value)
	}
	sort.Strings(urls)
	added := 0
	for _, value := range urls {
		mode, gameID := describeLaunchURL(value)
		fmt.Printf("%s", mode)
		if gameID != "" {
			fmt.Printf(" game-id=%s", gameID)
		}
		fmt.Printf("\n%s\n", value)
		if existing[value] {
			continue
		}
		record := captureRecord{
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			PID:       os.Getpid(),
			LaunchURL: value,
			Mode:      mode,
			GameID:    gameID,
			Source:    found[value].source,
			Event:     "discovered_http_launch",
		}
		if err := appendCapture(cfg.CaptureLog, record); err != nil {
			return err
		}
		added++
	}
	fmt.Printf("Discovered %d launch URL(s); appended %d new record(s) to %s\n", len(urls), added, cfg.CaptureLog)
	return nil
}

func launchCommand(args []string) error {
	set := flag.NewFlagSet("launch", flag.ContinueOnError)
	mode := set.String("mode", "", "BF3 launch mode: sp or mp")
	gameID := set.String("game-id", "", "Battlelog multiplayer game ID")
	rawURL := set.String("url", "", "captured localhost launch URL")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return usageError()
	}
	cfg, _, err := currentConfig()
	if err != nil {
		return err
	}
	launchURL := *rawURL
	launchMode := strings.ToUpper(*mode)
	if launchURL == "" {
		switch launchMode {
		case "SP":
			launchURL = buildBF3LaunchURL("SP", "")
		case "MP":
			if *gameID == "" {
				return errors.New("launch --mode mp requires --game-id")
			}
			launchURL = buildBF3LaunchURL("MP", *gameID)
		default:
			return errors.New("launch requires --url or --mode sp|mp")
		}
	} else {
		launchMode, *gameID = describeLaunchURL(launchURL)
	}
	record := captureRecord{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		PID:       os.Getpid(),
		LaunchURL: launchURL,
		Mode:      launchMode,
		GameID:    *gameID,
		Event:     "direct_http_launch",
	}
	if err := appendCapture(cfg.CaptureLog, record); err != nil {
		return err
	}
	fmt.Printf("Sending %s launch to ZClient: %s\n", launchMode, launchURL)
	return requestLaunchURL(launchURL)
}

func buildBF3LaunchURL(mode, gameID string) string {
	var command string
	if strings.EqualFold(mode, "MP") {
		command = fmt.Sprintf(`-webMode MP -Origin_NoAppFocus -loginToken WAHAHA_IMMA_ZLO_TOKEN -requestState State_ClaimReservation -requestStateParams "<data putinsquad=\"true\" gameid=\"%s\" role=\"soldier\" personaref=\"%%ZID%%\" levelmode=\"mp\" logintoken=\"WAHAHA_IMMA_ZLO_TOKEN\"></data>"`, gameID)
	} else {
		command = `-webMode SP -Origin_NoAppFocus -loginToken WAHAHA_IMMA_ZLO_TOKEN -requestState State_ResumeCampaign -requestStateParams "<data personaref=\"%ZID%\" levelmode=\"sp\" logintoken=\"WAHAHA_IMMA_ZLO_TOKEN\"></data>"`
	}
	escaped := strings.ReplaceAll(url.QueryEscape(command), "+", "%20")
	return "http://localhost:5080/ZLO/run?game=Z.BF3&cmd=" + escaped
}

func requestLaunchURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("parse launch URL: %w", err)
	}
	hostname := strings.ToLower(parsed.Hostname())
	if parsed.Scheme != "http" || (hostname != "localhost" && hostname != "127.0.0.1") || parsed.Port() != "5080" || !strings.EqualFold(parsed.Path, "/ZLO/run") {
		return errors.New("refusing request outside http://localhost:5080/ZLO/run")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Get(value)
	if err != nil {
		return fmt.Errorf("call ZClient launch endpoint: %w", err)
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if readErr != nil {
		return fmt.Errorf("read ZClient response: %w", readErr)
	}
	fmt.Printf("ZClient HTTP %s", response.Status)
	if len(body) != 0 {
		fmt.Printf(": %s", strings.TrimSpace(string(body)))
	}
	fmt.Println()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("ZClient returned HTTP %s", response.Status)
	}
	return nil
}

func describeLaunchURL(value string) (string, string) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "UNKNOWN", ""
	}
	command := parsed.Query().Get("cmd")
	mode := "UNKNOWN"
	if strings.Contains(command, "-webMode SP") {
		mode = "SP"
	} else if strings.Contains(command, "-webMode MP") {
		mode = "MP"
	}
	gameID := ""
	if match := regexp.MustCompile(`gameid=\\?"([0-9]+)`).FindStringSubmatch(command); len(match) == 2 {
		gameID = match[1]
	}
	return mode, gameID
}

func captureAndForward(uri string) error {
	cfg, _, err := currentConfig()
	if err != nil {
		return err
	}
	record := captureRecord{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		PID:       os.Getpid(),
		URI:       uri,
		Payload:   uri[len("zlo://"):],
		Argv:      append([]string(nil), os.Args...),
	}
	if err := appendCapture(cfg.CaptureLog, record); err != nil {
		return err
	}
	if err := forward(cfg, uri); err != nil {
		record.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
		record.Event = "forward_error"
		record.Error = err.Error()
		_ = appendCapture(cfg.CaptureLog, record)
		return err
	}
	return nil
}

func forward(cfg config, uri string) error {
	argv, replaced := substituteURI(cfg.OriginalArgv, uri)
	if !replaced {
		argv = append(argv, uri)
	}
	if len(argv) == 0 {
		return errors.New("saved original handler has no executable")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start original handler %q: %w", argv[0], err)
	}
	return cmd.Process.Release()
}

func substituteURI(argv []string, uri string) ([]string, bool) {
	result := append([]string(nil), argv...)
	replaced := false
	for index, value := range result {
		for _, token := range []string{"%1", "%L", "%l"} {
			if strings.Contains(value, token) {
				value = strings.ReplaceAll(value, token, uri)
				replaced = true
			}
		}
		result[index] = value
	}
	return result, replaced
}

type statePathSet struct {
	dir        string
	config     string
	captureLog string
}

func statePaths() (statePathSet, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		var err error
		base, err = os.UserConfigDir()
		if err != nil {
			return statePathSet{}, fmt.Errorf("locate user data directory: %w", err)
		}
	}
	dir := filepath.Join(base, "ZloUriShim")
	return statePathSet{
		dir:        dir,
		config:     filepath.Join(dir, "config.json"),
		captureLog: filepath.Join(dir, "captures.jsonl"),
	}, nil
}

func currentConfig() (config, string, error) {
	paths, err := statePaths()
	if err != nil {
		return config{}, "", err
	}
	cfg, err := loadConfig(paths.config)
	if err != nil {
		return config{}, paths.config, fmt.Errorf("load shim config (run install first): %w", err)
	}
	return cfg, paths.config, nil
}

func saveConfig(path string, cfg config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode shim config: %w", err)
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write shim config: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("commit shim config: %w", err)
	}
	return nil
}

func loadConfig(path string) (config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return config{}, err
	}
	if cfg.Version != configVersion || len(cfg.OriginalArgv) == 0 || cfg.CaptureLog == "" {
		return config{}, errors.New("unsupported or incomplete config")
	}
	return cfg, nil
}

func appendCapture(path string, record captureRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create capture directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open capture log: %w", err)
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(record); err != nil {
		return fmt.Errorf("append capture: %w", err)
	}
	return nil
}

func lastCapturedLaunch(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open capture log: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	last := ""
	for scanner.Scan() {
		var record captureRecord
		if json.Unmarshal(scanner.Bytes(), &record) != nil {
			continue
		}
		if record.LaunchURL != "" {
			last = record.LaunchURL
		} else if record.Event == "" && record.URI != "" {
			last = record.URI
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read capture log: %w", err)
	}
	if last == "" {
		return "", errors.New("capture log contains no launch URL")
	}
	return last, nil
}

func capturedLaunchSet(path string) (map[string]bool, error) {
	result := make(map[string]bool)
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		var record captureRecord
		if json.Unmarshal(scanner.Bytes(), &record) == nil && record.LaunchURL != "" {
			result[record.LaunchURL] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read capture log: %w", err)
	}
	return result, nil
}

func browserCacheSources(explicit string) ([]string, error) {
	if explicit != "" {
		absolute, err := filepath.Abs(explicit)
		if err != nil {
			return nil, fmt.Errorf("resolve cache path: %w", err)
		}
		info, err := os.Stat(absolute)
		if err != nil {
			return nil, fmt.Errorf("inspect cache path: %w", err)
		}
		if !info.IsDir() {
			return []string{absolute}, nil
		}
		return regularFiles(absolute), nil
	}
	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		return nil, errors.New("LOCALAPPDATA is not set; use discover --cache PATH")
	}
	patterns := []string{
		filepath.Join(local, "Microsoft", "Edge", "User Data", "*", "Cache", "Cache_Data"),
		filepath.Join(local, "Google", "Chrome", "User Data", "*", "Cache", "Cache_Data"),
		filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data", "*", "Cache", "Cache_Data"),
	}
	seen := make(map[string]bool)
	var sources []string
	for _, pattern := range patterns {
		directories, _ := filepath.Glob(pattern)
		for _, directory := range directories {
			for _, path := range regularFiles(directory) {
				if !seen[path] {
					seen[path] = true
					sources = append(sources, path)
				}
			}
		}
	}
	if len(sources) == 0 {
		return nil, errors.New("no supported Chromium cache found; use discover --cache PATH")
	}
	return sources, nil
}

func regularFiles(directory string) []string {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			result = append(result, filepath.Join(directory, entry.Name()))
		}
	}
	return result
}

func readSharedFile(path string, maximum int64) ([]byte, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(
		pathPtr,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		syscall.CloseHandle(handle)
		return nil, errors.New("wrap shared cache handle")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	return data, nil
}

func registerProtocol(shimPath string) error {
	values := []struct {
		key   string
		name  string
		value string
	}{
		{userProtocolKey, "", "URL:zlo protocol"},
		{userProtocolKey, "URL Protocol", ""},
		{userProtocolKey, shimMarker, shimPath},
		{userProtocolKey + `\DefaultIcon`, "", shimPath + ",0"},
		{userProtocolKey + `\` + commandSubkey, "", quoteWindowsArg(shimPath) + ` "%1"`},
	}
	for _, item := range values {
		key, err := createKey(hkeyCurrentUser, item.key)
		if err != nil {
			_ = deleteTree(hkeyCurrentUser, userProtocolKey)
			return fmt.Errorf("create registry key %s: %w", item.key, err)
		}
		err = setString(key, item.name, item.value)
		closeKey(key)
		if err != nil {
			_ = deleteTree(hkeyCurrentUser, userProtocolKey)
			return fmt.Errorf("set registry value %s\\%s: %w", item.key, item.name, err)
		}
	}
	return nil
}

func openKey(root syscall.Handle, path string, access uint32) (syscall.Handle, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var key syscall.Handle
	status, _, _ := regOpenKeyExW.Call(uintptr(root), uintptr(unsafe.Pointer(pathPtr)), 0, uintptr(access), uintptr(unsafe.Pointer(&key)))
	if status == errorFileNotFound {
		return 0, os.ErrNotExist
	}
	if status != errorSuccess {
		return 0, syscall.Errno(status)
	}
	return key, nil
}

func createKey(root syscall.Handle, path string) (syscall.Handle, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var key syscall.Handle
	var disposition uint32
	status, _, _ := regCreateKeyExW.Call(
		uintptr(root), uintptr(unsafe.Pointer(pathPtr)), 0, 0, 0, keyRead|keyWrite, 0,
		uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&disposition)),
	)
	if status != errorSuccess {
		return 0, syscall.Errno(status)
	}
	return key, nil
}

func keyExists(root syscall.Handle, path string) (bool, error) {
	key, err := openKey(root, path, keyRead)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	closeKey(key)
	return true, nil
}

func queryString(root syscall.Handle, path, name string) (string, error) {
	key, err := openKey(root, path, keyRead)
	if err != nil {
		return "", err
	}
	defer closeKey(key)
	return queryStringValue(key, name)
}

func queryStringValue(key syscall.Handle, name string) (string, error) {
	var namePtr *uint16
	var err error
	if name != "" {
		namePtr, err = syscall.UTF16PtrFromString(name)
		if err != nil {
			return "", err
		}
	}
	var valueType uint32
	var size uint32
	status, _, _ := regQueryValueExW.Call(
		uintptr(key), uintptr(unsafe.Pointer(namePtr)), 0, uintptr(unsafe.Pointer(&valueType)), 0, uintptr(unsafe.Pointer(&size)),
	)
	if status == errorFileNotFound {
		return "", os.ErrNotExist
	}
	if status != errorSuccess {
		return "", syscall.Errno(status)
	}
	if valueType != regSZ {
		return "", fmt.Errorf("registry value has type %d, expected REG_SZ", valueType)
	}
	buffer := make([]uint16, (size+1)/2)
	status, _, _ = regQueryValueExW.Call(
		uintptr(key), uintptr(unsafe.Pointer(namePtr)), 0, uintptr(unsafe.Pointer(&valueType)),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)),
	)
	if status != errorSuccess {
		return "", syscall.Errno(status)
	}
	return syscall.UTF16ToString(buffer), nil
}

func setString(key syscall.Handle, name, value string) error {
	var namePtr *uint16
	var err error
	if name != "" {
		namePtr, err = syscall.UTF16PtrFromString(name)
		if err != nil {
			return err
		}
	}
	data, err := syscall.UTF16FromString(value)
	if err != nil {
		return err
	}
	status, _, _ := regSetValueExW.Call(
		uintptr(key), uintptr(unsafe.Pointer(namePtr)), 0, regSZ,
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)*2),
	)
	if status != errorSuccess {
		return syscall.Errno(status)
	}
	return nil
}

func deleteTree(root syscall.Handle, path string) error {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	status, _, _ := regDeleteTreeW.Call(uintptr(root), uintptr(unsafe.Pointer(pathPtr)))
	if status == errorFileNotFound {
		return os.ErrNotExist
	}
	if status != errorSuccess {
		return syscall.Errno(status)
	}
	return nil
}

func closeKey(key syscall.Handle) {
	if key != 0 {
		regCloseKey.Call(uintptr(key))
	}
}

func splitWindowsCommandLine(command string) ([]string, error) {
	commandPtr, err := syscall.UTF16PtrFromString(command)
	if err != nil {
		return nil, err
	}
	var argc int32
	argvPtr, _, callErr := commandLineToArgv.Call(uintptr(unsafe.Pointer(commandPtr)), uintptr(unsafe.Pointer(&argc)))
	if argvPtr == 0 {
		return nil, callErr
	}
	defer localFree.Call(argvPtr)
	pointers := unsafe.Slice((**uint16)(unsafe.Pointer(argvPtr)), int(argc))
	args := make([]string, 0, argc)
	for _, pointer := range pointers {
		args = append(args, utf16PtrToString(pointer))
	}
	return args, nil
}

func utf16PtrToString(pointer *uint16) string {
	if pointer == nil {
		return ""
	}
	length := 0
	for *(*uint16)(unsafe.Add(unsafe.Pointer(pointer), uintptr(length*2))) != 0 {
		length++
	}
	return syscall.UTF16ToString(unsafe.Slice(pointer, length))
}

func quoteWindowsArg(value string) string {
	if value != "" && !strings.ContainsAny(value, " \t\n\v\"") {
		return value
	}
	var result strings.Builder
	result.WriteByte('"')
	backslashes := 0
	for _, char := range value {
		if char == '\\' {
			backslashes++
			continue
		}
		if char == '"' {
			result.WriteString(strings.Repeat("\\", backslashes*2+1))
			result.WriteRune(char)
			backslashes = 0
			continue
		}
		result.WriteString(strings.Repeat("\\", backslashes))
		backslashes = 0
		result.WriteRune(char)
	}
	result.WriteString(strings.Repeat("\\", backslashes*2))
	result.WriteByte('"')
	return result.String()
}

func samePath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	if leftErr == nil && rightErr == nil {
		left, right = filepath.Clean(leftAbs), filepath.Clean(rightAbs)
	}
	return strings.EqualFold(left, right)
}

func notifyAssociationChanged() {
	const shcneAssocChanged = 0x08000000
	shChangeNotify.Call(shcneAssocChanged, 0, 0, 0)
}
