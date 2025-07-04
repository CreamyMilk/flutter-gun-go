package main

import (
	"archive/zip"
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Constants
const (
	VERSION = "0.8.4"
	TIMEOUT = 30 * time.Second

	// Engine hash CSV URL
	ENGINE_HASH_URL = "https://raw.githubusercontent.com/Impact-I/reFlutter/main/enginehash.csv"

	// Default Burp Suite proxy port
	DEFAULT_PROXY_PORT = 8083
)

// EngineInfo represents Flutter engine information
type EngineInfo struct {
	Hash     string `json:"hash"`
	Commit   string `json:"commit"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
	Mode     string `json:"mode"`
}

// ReFlutterConfig holds configuration for the reFlutter process
type ReFlutterConfig struct {
	InputFile    string
	OutputFile   string
	ProxyIP      string
	ProxyPort    int
	Platform     string
	Architecture string
	Mode         string
}

// ReFlutter main struct
type ReFlutter struct {
	config       ReFlutterConfig
	engineHashes []EngineInfo
	httpClient   *http.Client
}

// NewReFlutter creates a new ReFlutter instance
func NewReFlutter(config ReFlutterConfig) *ReFlutter {
	return &ReFlutter{
		config: config,
		httpClient: &http.Client{
			Timeout: TIMEOUT,
		},
	}
}

// LoadEngineHashes loads engine hash information from CSV
func (r *ReFlutter) LoadEngineHashes() error {
	resp, err := r.httpClient.Get(ENGINE_HASH_URL)
	if err != nil {
		return fmt.Errorf("failed to fetch engine hashes: %w", err)
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	// Skip header line
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) >= 6 {
			r.engineHashes = append(r.engineHashes, EngineInfo{
				Hash:     parts[0],
				Commit:   parts[1],
				Version:  parts[2],
				Platform: parts[3],
				Arch:     parts[4],
				Mode:     parts[5],
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading engine hashes: %w", err)
	}

	return nil
}

// ExtractAPK extracts an APK file to a directory
func (r *ReFlutter) ExtractAPK(apkPath, extractDir string) error {
	reader, err := zip.OpenReader(apkPath)
	if err != nil {
		return fmt.Errorf("failed to open APK: %w", err)
	}
	defer reader.Close()

	os.MkdirAll(extractDir, 0755)

	for _, file := range reader.File {
		path := filepath.Join(extractDir, file.Name)

		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.FileInfo().Mode())
			continue
		}

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		fileReader, err := file.Open()
		if err != nil {
			return err
		}
		defer fileReader.Close()

		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
		if err != nil {
			return err
		}
		defer targetFile.Close()

		_, err = io.Copy(targetFile, fileReader)
		if err != nil {
			return err
		}
	}

	return nil
}

// FindLibApp finds the libapp.so file in the extracted APK
func (r *ReFlutter) FindLibApp(extractDir string) (string, error) {
	var libappPath string

	err := filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if strings.HasSuffix(info.Name(), "libapp.so") {
			libappPath = path
			return filepath.SkipDir
		}

		return nil
	})

	if err != nil {
		return "", err
	}

	if libappPath == "" {
		return "", fmt.Errorf("libapp.so not found in APK")
	}

	return libappPath, nil
}

// CalculateSnapshotHash calculates the MD5 hash of the snapshot
func (r *ReFlutter) CalculateSnapshotHash(libappPath string) (string, error) {
	file, err := os.Open(libappPath)
	if err != nil {
		return "", fmt.Errorf("failed to open libapp.so: %w", err)
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to calculate hash: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// FindEngineInfo finds matching engine information for the given hash
func (r *ReFlutter) FindEngineInfo(hash string) (*EngineInfo, error) {
	for _, engine := range r.engineHashes {
		if engine.Hash == hash {
			return &engine, nil
		}
	}
	return nil, fmt.Errorf("engine not found for hash: %s", hash)
}

// DownloadPatchedEngine downloads the patched Flutter engine
func (r *ReFlutter) DownloadPatchedEngine(engineInfo *EngineInfo) ([]byte, error) {
	// This would download from the reFlutter releases or build server
	// For now, we'll simulate this with a placeholder

	url := fmt.Sprintf("https://github.com/Impact-I/reFlutter/releases/download/engine-%s/libapp.so", engineInfo.Hash)

	resp, err := r.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download patched engine: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download patched engine: status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// PatchAPK patches the APK with the new engine
func (r *ReFlutter) PatchAPK(extractDir, libappPath string, patchedEngine []byte) error {
	// Replace the original libapp.so with patched version
	err := os.WriteFile(libappPath, patchedEngine, 0644)
	if err != nil {
		return fmt.Errorf("failed to write patched engine: %w", err)
	}

	// Inject proxy configuration
	err = r.InjectProxyConfig(extractDir)
	if err != nil {
		return fmt.Errorf("failed to inject proxy config: %w", err)
	}

	return nil
}

// InjectProxyConfig injects proxy configuration into the APK
func (r *ReFlutter) InjectProxyConfig(extractDir string) error {
	// Find AndroidManifest.xml
	manifestPath := filepath.Join(extractDir, "AndroidManifest.xml")

	// Read manifest
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read AndroidManifest.xml: %w", err)
	}

	// Add network security config (this is a simplified approach)
	// In a real implementation, you would need to properly parse and modify the XML
	proxyConfig := fmt.Sprintf(`
		<meta-data
			android:name="flutter.proxy"
			android:value="%s:%d" />
	`, r.config.ProxyIP, r.config.ProxyPort)

	// Insert proxy config before </application>
	modifiedManifest := strings.Replace(string(manifestData), "</application>", proxyConfig+"</application>", 1)

	// Write back
	err = os.WriteFile(manifestPath, []byte(modifiedManifest), 0644)
	if err != nil {
		return fmt.Errorf("failed to write modified manifest: %w", err)
	}

	return nil
}

// RepackAPK repacks the modified APK
func (r *ReFlutter) RepackAPK(extractDir, outputPath string) error {
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output APK: %w", err)
	}
	defer outputFile.Close()

	zipWriter := zip.NewWriter(outputFile)
	defer zipWriter.Close()

	return filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(extractDir, path)
		if err != nil {
			return err
		}

		// Use forward slashes for ZIP entries
		relPath = strings.Replace(relPath, "\\", "/", -1)

		zipFile, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}

		fsFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fsFile.Close()

		_, err = io.Copy(zipFile, fsFile)
		return err
	})
}

// ProcessAPK processes an APK file
func (r *ReFlutter) ProcessAPK(apkPath string) error {
	fmt.Printf("Processing APK: %s\n", apkPath)

	// Create temporary directory for extraction
	tmpDir, err := os.MkdirTemp("", "reflutter_*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Extract APK
	fmt.Println("Extracting APK...")
	err = r.ExtractAPK(apkPath, tmpDir)
	if err != nil {
		return fmt.Errorf("failed to extract APK: %w", err)
	}

	// Find libapp.so
	fmt.Println("Finding libapp.so...")
	libappPath, err := r.FindLibApp(tmpDir)
	if err != nil {
		return fmt.Errorf("failed to find libapp.so: %w", err)
	}

	// Calculate snapshot hash
	fmt.Println("Calculating snapshot hash...")
	hash, err := r.CalculateSnapshotHash(libappPath)
	if err != nil {
		return fmt.Errorf("failed to calculate snapshot hash: %w", err)
	}

	fmt.Printf("SnapshotHash: %s\n", hash)

	// Find engine info
	fmt.Println("Finding engine information...")
	engineInfo, err := r.FindEngineInfo(hash)
	if err != nil {
		return fmt.Errorf("failed to find engine info: %w", err)
	}

	// Download patched engine
	fmt.Println("Downloading patched engine...")
	patchedEngine, err := r.DownloadPatchedEngine(engineInfo)
	if err != nil {
		return fmt.Errorf("failed to download patched engine: %w", err)
	}

	// Patch APK
	fmt.Println("Patching APK...")
	err = r.PatchAPK(tmpDir, libappPath, patchedEngine)
	if err != nil {
		return fmt.Errorf("failed to patch APK: %w", err)
	}

	// Repack APK
	fmt.Println("Repacking APK...")
	err = r.RepackAPK(tmpDir, r.config.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to repack APK: %w", err)
	}

	fmt.Printf("The resulting apk file: %s\n", r.config.OutputFile)
	fmt.Println("Please sign the apk file")
	fmt.Printf("Configure Burp Suite proxy server to listen on *:%d\n", r.config.ProxyPort)
	fmt.Println("Proxy Tab -> Options -> Proxy Listeners -> Edit -> Binding Tab")
	fmt.Println("Then enable invisible proxying in Request Handling Tab")
	fmt.Println("Support Invisible Proxying -> true")

	return nil
}

// ProcessIPA processes an IPA file (iOS)
func (r *ReFlutter) ProcessIPA(ipaPath string) error {
	fmt.Printf("Processing IPA: %s\n", ipaPath)

	// Create temporary directory for extraction
	tmpDir, err := os.MkdirTemp("", "reflutter_ios_*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Extract IPA (similar to APK extraction)
	fmt.Println("Extracting IPA...")
	err = r.ExtractAPK(ipaPath, tmpDir) // IPA is also a ZIP file
	if err != nil {
		return fmt.Errorf("failed to extract IPA: %w", err)
	}

	// Find App.framework
	fmt.Println("Finding App.framework...")
	var appFrameworkPath string
	err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(path, "App.framework") && strings.HasSuffix(path, "App") {
			appFrameworkPath = path
			return filepath.SkipDir
		}
		return nil
	})

	if appFrameworkPath == "" {
		return fmt.Errorf("App.framework not found in IPA")
	}

	// Calculate snapshot hash
	fmt.Println("Calculating snapshot hash...")
	hash, err := r.CalculateSnapshotHash(appFrameworkPath)
	if err != nil {
		return fmt.Errorf("failed to calculate snapshot hash: %w", err)
	}

	fmt.Printf("SnapshotHash: %s\n", hash)

	// Find engine info
	fmt.Println("Finding engine information...")
	engineInfo, err := r.FindEngineInfo(hash)
	if err != nil {
		return fmt.Errorf("failed to find engine info: %w", err)
	}

	// Download patched engine (iOS version)
	fmt.Println("Downloading patched engine...")
	patchedEngine, err := r.DownloadPatchedEngine(engineInfo)
	if err != nil {
		return fmt.Errorf("failed to download patched engine: %w", err)
	}

	// Replace App.framework binary
	err = os.WriteFile(appFrameworkPath, patchedEngine, 0755)
	if err != nil {
		return fmt.Errorf("failed to write patched engine: %w", err)
	}

	// Repack IPA
	fmt.Println("Repacking IPA...")
	err = r.RepackAPK(tmpDir, r.config.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to repack IPA: %w", err)
	}

	fmt.Printf("The resulting ipa file: %s\n", r.config.OutputFile)
	fmt.Println("Configure Burp Suite proxy server settings as described in the documentation")

	return nil
}

// GetUserInput gets user input for proxy IP
func GetUserInput(prompt string) string {
	fmt.Print(prompt)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return scanner.Text()
}

// ValidateIP validates an IP address format
func ValidateIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return false
		}
	}

	return true
}

// ShowUsage displays usage information
func ShowUsage() {
	fmt.Printf("reFlutter v%s - Flutter Reverse Engineering Framework\n", VERSION)
	fmt.Println("Usage: reflutter <input_file> [options]")
	fmt.Println("\nOptions:")
	fmt.Println("  -o, --output <file>    Output file path")
	fmt.Println("  -p, --proxy <ip>       Proxy IP address")
	fmt.Println("  --port <port>          Proxy port (default: 8083)")
	fmt.Println("  -h, --help             Show this help message")
	fmt.Println("\nExamples:")
	fmt.Println("  reflutter app.apk")
	fmt.Println("  reflutter app.ipa -o patched_app.ipa")
	fmt.Println("  reflutter app.apk --proxy 192.168.1.100 --port 8080")
}

func main() {
	if len(os.Args) < 2 {
		ShowUsage()
		os.Exit(1)
	}

	inputFile := os.Args[1]
	if inputFile == "-h" || inputFile == "--help" {
		ShowUsage()
		os.Exit(0)
	}

	// Parse command line arguments
	config := ReFlutterConfig{
		InputFile: inputFile,
		ProxyPort: DEFAULT_PROXY_PORT,
		Platform:  "android",
		Mode:      "release",
	}

	// Determine output file
	if strings.HasSuffix(inputFile, ".apk") {
		config.OutputFile = strings.TrimSuffix(inputFile, ".apk") + ".RE.apk"
		config.Platform = "android"
	} else if strings.HasSuffix(inputFile, ".ipa") {
		config.OutputFile = strings.TrimSuffix(inputFile, ".ipa") + ".RE.ipa"
		config.Platform = "ios"
	} else {
		fmt.Println("Error: Input file must be .apk or .ipa")
		os.Exit(1)
	}

	// Parse additional arguments
	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch arg {
		case "-o", "--output":
			if i+1 < len(os.Args) {
				config.OutputFile = os.Args[i+1]
				i++
			}
		case "-p", "--proxy":
			if i+1 < len(os.Args) {
				config.ProxyIP = os.Args[i+1]
				i++
			}
		case "--port":
			if i+1 < len(os.Args) {
				port, err := strconv.Atoi(os.Args[i+1])
				if err != nil {
					fmt.Println("Error: Invalid port number")
					os.Exit(1)
				}
				config.ProxyPort = port
				i++
			}
		}
	}

	// Get proxy IP if not provided
	if config.ProxyIP == "" {
		for {
			proxyIP := GetUserInput("Please enter your Burp Suite IP: ")
			if ValidateIP(proxyIP) {
				config.ProxyIP = proxyIP
				break
			}
			fmt.Println("Invalid IP address format. Please try again.")
		}
	}

	// Check if input file exists
	if _, err := os.Stat(config.InputFile); os.IsNotExist(err) {
		fmt.Printf("Error: Input file '%s' does not exist\n", config.InputFile)
		os.Exit(1)
	}

	// Create ReFlutter instance
	reflutter := NewReFlutter(config)

	// Load engine hashes
	fmt.Println("Loading engine hash information...")
	err := reflutter.LoadEngineHashes()
	if err != nil {
		log.Fatalf("Failed to load engine hashes: %v", err)
	}

	// Process the file
	if config.Platform == "android" {
		err = reflutter.ProcessAPK(config.InputFile)
	} else {
		err = reflutter.ProcessIPA(config.InputFile)
	}

	if err != nil {
		log.Fatalf("Failed to process file: %v", err)
	}

	fmt.Println("Processing completed successfully!")
}
