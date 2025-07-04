// utils.go - Utility functions for reFlutter Go implementation
package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// FlutterEngine represents a Flutter engine with patching capabilities
type FlutterEngine struct {
	Path         string
	Hash         string
	Architecture string
	Platform     string
	Version      string
}

// DartSnapshot represents a Dart snapshot structure
type DartSnapshot struct {
	Magic    uint32
	Version  uint32
	Features uint64
	Length   uint32
	Data     []byte
}

// SnapshotAnalyzer analyzes Dart snapshots for reverse engineering
type SnapshotAnalyzer struct {
	snapshot *DartSnapshot
	symbols  []Symbol
}

// Symbol represents a Dart symbol
type Symbol struct {
	Name    string
	Address uint64
	Size    uint64
	Type    string
}

// AndroidManifest represents Android manifest modifications
type AndroidManifest struct {
	XMLData     []byte
	Permissions []string
	Activities  []string
	Services    []string
}

// IOSInfoPlist represents iOS Info.plist modifications
type IOSInfoPlist struct {
	PlistData []byte
	Keys      map[string]interface{}
}

// PatchManager handles various patching operations
type PatchManager struct {
	platform string
	arch     string
	patches  []Patch
}

// Patch represents a single patch operation
type Patch struct {
	Name        string
	Description string
	Offset      uint64
	Original    []byte
	Replacement []byte
	Applied     bool
}

// NewSnapshotAnalyzer creates a new snapshot analyzer
func NewSnapshotAnalyzer(snapshotPath string) (*SnapshotAnalyzer, error) {
	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot: %w", err)
	}

	snapshot, err := parseSnapshot(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse snapshot: %w", err)
	}

	return &SnapshotAnalyzer{
		snapshot: snapshot,
		symbols:  []Symbol{},
	}, nil
}

// parseSnapshot parses a Dart snapshot from binary data
func parseSnapshot(data []byte) (*DartSnapshot, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("snapshot too small")
	}

	reader := bytes.NewReader(data)
	var snapshot DartSnapshot

	// Read magic number
	err := binary.Read(reader, binary.LittleEndian, &snapshot.Magic)
	if err != nil {
		return nil, err
	}

	// Read version
	err = binary.Read(reader, binary.LittleEndian, &snapshot.Version)
	if err != nil {
		return nil, err
	}

	// Read features
	err = binary.Read(reader, binary.LittleEndian, &snapshot.Features)
	if err != nil {
		return nil, err
	}

	// Read length
	err = binary.Read(reader, binary.LittleEndian, &snapshot.Length)
	if err != nil {
		return nil, err
	}

	// Read remaining data
	snapshot.Data = make([]byte, len(data)-20)
	copy(snapshot.Data, data[20:])

	return &snapshot, nil
}

// ExtractSymbols extracts symbols from the snapshot
func (sa *SnapshotAnalyzer) ExtractSymbols() error {
	// This is a simplified symbol extraction
	// In a real implementation, you would need to parse the Dart VM snapshot format

	// Look for common Dart patterns
	patterns := []string{
		`Library:'package:([^']+)'`,
		`Class: ([A-Za-z_][A-Za-z0-9_]*) extends ([A-Za-z_][A-Za-z0-9_]*)`,
		`Function '([^']+)':`,
		`Code Offset: _kDartIsolateSnapshotInstructions \+ (0x[0-9a-fA-F]+)`,
	}

	data := string(sa.snapshot.Data)

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(data, -1)

		for _, match := range matches {
			if len(match) > 1 {
				symbol := Symbol{
					Name: match[1],
					Type: "function",
				}

				// Extract address if present
				if len(match) > 2 && strings.HasPrefix(match[2], "0x") {
					fmt.Sscanf(match[2], "0x%x", &symbol.Address)
				}

				sa.symbols = append(sa.symbols, symbol)
			}
		}
	}

	return nil
}

// GetSymbols returns extracted symbols
func (sa *SnapshotAnalyzer) GetSymbols() []Symbol {
	return sa.symbols
}

// FindELFSymbols finds symbols in ELF file (libapp.so)
func FindELFSymbols(filePath string) ([]Symbol, error) {
	file, err := elf.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF file: %w", err)
	}
	defer file.Close()

	var symbols []Symbol

	// Get dynamic symbols
	dynSyms, err := file.DynamicSymbols()
	if err == nil {
		for _, sym := range dynSyms {
			symbols = append(symbols, Symbol{
				Name:    sym.Name,
				Address: sym.Value,
				Size:    sym.Size,
				Type:    "dynamic",
			})
		}
	}

	// Get regular symbols
	syms, err := file.Symbols()
	if err == nil {
		for _, sym := range syms {
			symbols = append(symbols, Symbol{
				Name:    sym.Name,
				Address: sym.Value,
				Size:    sym.Size,
				Type:    "regular",
			})
		}
	}

	return symbols, nil
}

// NewPatchManager creates a new patch manager
func NewPatchManager(platform, arch string) *PatchManager {
	return &PatchManager{
		platform: platform,
		arch:     arch,
		patches:  []Patch{},
	}
}

// AddSocketPatch adds socket interception patch
func (pm *PatchManager) AddSocketPatch() {
	patch := Patch{
		Name:        "socket_intercept",
		Description: "Intercepts socket connections for traffic monitoring",
		Original:    []byte{0x40, 0x00, 0x80, 0xD2}, // Example ARM64 instruction
		Replacement: []byte{0x40, 0x00, 0x80, 0xD2}, // Modified instruction
	}
	pm.patches = append(pm.patches, patch)
}

// AddDartPatch adds Dart debugging patch
func (pm *PatchManager) AddDartPatch() {
	patch := Patch{
		Name:        "dart_debug",
		Description: "Enables Dart debugging and class/function printing",
		Original:    []byte{0x1F, 0x20, 0x03, 0xD5}, // Example NOP instruction
		Replacement: []byte{0x00, 0x00, 0x80, 0xD2}, // Modified instruction
	}
	pm.patches = append(pm.patches, patch)
}

// ApplyPatches applies all patches to the binary
func (pm *PatchManager) ApplyPatches(binaryPath string) error {
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to read binary: %w", err)
	}

	modified := false
	for i := range pm.patches {
		patch := &pm.patches[i]

		// Find the offset of the original bytes
		offset := bytes.Index(data, patch.Original)
		if offset == -1 {
			fmt.Printf("Warning: Pattern not found for patch %s\n", patch.Name)
			continue
		}

		// Apply the patch
		copy(data[offset:], patch.Replacement)
		patch.Applied = true
		patch.Offset = uint64(offset)
		modified = true

		fmt.Printf("Applied patch: %s at offset 0x%x\n", patch.Name, offset)
	}

	if modified {
		// Write the modified binary back
		err = os.WriteFile(binaryPath, data, 0755)
		if err != nil {
			return fmt.Errorf("failed to write patched binary: %w", err)
		}
	}

	return nil
}

// GetPatchStatus returns the status of all patches
func (pm *PatchManager) GetPatchStatus() []Patch {
	return pm.patches
}

// NetworkSecurityConfig represents Android network security configuration
type NetworkSecurityConfig struct {
	XMLContent string
}

// GenerateNetworkSecurityConfig generates network security config for proxy
func GenerateNetworkSecurityConfig(proxyIP string, proxyPort int) *NetworkSecurityConfig {
	xml := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">%s</domain>
        <domain includeSubdomains="true">localhost</domain>
        <domain includeSubdomains="true">127.0.0.1</domain>
        <domain includeSubdomains="true">10.0.0.0/8</domain>
        <domain includeSubdomains="true">172.16.0.0/12</domain>
        <domain includeSubdomains="true">192.168.0.0/16</domain>
    </domain-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
</network-security-config>`, proxyIP)

	return &NetworkSecurityConfig{XMLContent: xml}
}

// AndroidManifestPatcher handles Android manifest modifications
type AndroidManifestPatcher struct {
	manifestPath string
	originalData []byte
}

// NewAndroidManifestPatcher creates a new Android manifest patcher
func NewAndroidManifestPatcher(manifestPath string) (*AndroidManifestPatcher, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	return &AndroidManifestPatcher{
		manifestPath: manifestPath,
		originalData: data,
	}, nil
}

// AddNetworkSecurityConfig adds network security configuration
func (amp *AndroidManifestPatcher) AddNetworkSecurityConfig(configPath string) error {
	manifest := string(amp.originalData)

	// Add network security config attribute to application tag
	applicationTag := `<application`
	networkSecurityAttr := `android:networkSecurityConfig="@xml/network_security_config"`

	if strings.Contains(manifest, applicationTag) {
		// Find the application tag and add the attribute
		re := regexp.MustCompile(`<application([^>]*)>`)
		manifest = re.ReplaceAllStringFunc(manifest, func(match string) string {
			if !strings.Contains(match, "networkSecurityConfig") {
				// Insert before the closing >
				return strings.Replace(match, ">", " "+networkSecurityAttr+">", 1)
			}
			return match
		})
	}

	// Add internet permission if not present
	if !strings.Contains(manifest, "android.permission.INTERNET") {
		internetPermission := `<uses-permission android:name="android.permission.INTERNET" />`
		// Insert after the first line (typically <?xml version...?>)
		lines := strings.Split(manifest, "\n")
		if len(lines) > 1 {
			lines = append(lines[:1], append([]string{internetPermission}, lines[1:]...)...)
			manifest = strings.Join(lines, "\n")
		}
	}

	// Write back the modified manifest
	return os.WriteFile(amp.manifestPath, []byte(manifest), 0644)
}

// AddProxyPermissions adds necessary permissions for proxy functionality
func (amp *AndroidManifestPatcher) AddProxyPermissions() error {
	manifest := string(amp.originalData)

	permissions := []string{
		"android.permission.INTERNET",
		"android.permission.ACCESS_NETWORK_STATE",
		"android.permission.ACCESS_WIFI_STATE",
		"android.permission.WRITE_EXTERNAL_STORAGE",
		"android.permission.READ_EXTERNAL_STORAGE",
	}

	for _, perm := range permissions {
		if !strings.Contains(manifest, perm) {
			permissionTag := fmt.Sprintf(`<uses-permission android:name="%s" />`, perm)
			// Insert after the first line
			lines := strings.Split(manifest, "\n")
			if len(lines) > 1 {
				lines = append(lines[:1], append([]string{permissionTag}, lines[1:]...)...)
				manifest = strings.Join(lines, "\n")
			}
		}
	}

	return os.WriteFile(amp.manifestPath, []byte(manifest), 0644)
}

// IOSInfoPlistPatcher handles iOS Info.plist modifications
type IOSInfoPlistPatcher struct {
	plistPath    string
	originalData []byte
}

// NewIOSInfoPlistPatcher creates a new iOS Info.plist patcher
func NewIOSInfoPlistPatcher(plistPath string) (*IOSInfoPlistPatcher, error) {
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Info.plist: %w", err)
	}

	return &IOSInfoPlistPatcher{
		plistPath:    plistPath,
		originalData: data,
	}, nil
}

// AddNetworkingPermissions adds networking permissions for iOS
func (ipp *IOSInfoPlistPatcher) AddNetworkingPermissions() error {
	plist := string(ipp.originalData)

	// Add NSAppTransportSecurity settings
	atsSettings := `
	<key>NSAppTransportSecurity</key>
	<dict>
		<key>NSAllowsArbitraryLoads</key>
		<true/>
		<key>NSAllowsArbitraryLoadsInWebContent</key>
		<true/>
		<key>NSAllowsArbitraryLoadsForMedia</key>
		<true/>
	</dict>`

	// Insert before </dict> at the end
	if strings.Contains(plist, "</dict>") && !strings.Contains(plist, "NSAppTransportSecurity") {
		lastDictIndex := strings.LastIndex(plist, "</dict>")
		plist = plist[:lastDictIndex] + atsSettings + "\n" + plist[lastDictIndex:]
	}

	return os.WriteFile(ipp.plistPath, []byte(plist), 0644)
}

// FridaScriptGenerator generates Frida scripts for dynamic analysis
type FridaScriptGenerator struct {
	platform string
	arch     string
}

// NewFridaScriptGenerator creates a new Frida script generator
func NewFridaScriptGenerator(platform, arch string) *FridaScriptGenerator {
	return &FridaScriptGenerator{
		platform: platform,
		arch:     arch,
	}
}

// GenerateBaseScript generates a base Frida script for Flutter analysis
func (fsg *FridaScriptGenerator) GenerateBaseScript(baseAddress uint64) string {
	script := fmt.Sprintf(`
// reFlutter Frida Script - Generated for %s/%s
// Base address: 0x%x

Java.perform(function() {
    console.log("[+] reFlutter Frida script loaded");
    
    // Hook Flutter engine functions
    var libapp = Module.load("libapp.so");
    var base_addr = ptr("0x%x");
    
    // Hook Dart_Initialize
    var dart_init = libapp.getExportByName("Dart_Initialize");
    if (dart_init) {
        Interceptor.attach(dart_init, {
            onEnter: function(args) {
                console.log("[+] Dart_Initialize called");
            },
            onLeave: function(retval) {
                console.log("[+] Dart_Initialize finished");
            }
        });
    }
    
    // Hook socket operations
    var socket_func = libapp.getExportByName("socket");
    if (socket_func) {
        Interceptor.attach(socket_func, {
            onEnter: function(args) {
                console.log("[+] Socket called with domain: " + args[0] + 
                          ", type: " + args[1] + ", protocol: " + args[2]);
            },
            onLeave: function(retval) {
                console.log("[+] Socket returned: " + retval);
            }
        });
    }
    
    // Hook connect operations  
    var connect_func = libapp.getExportByName("connect");
    if (connect_func) {
        Interceptor.attach(connect_func, {
            onEnter: function(args) {
                var sockfd = args[0];
                var addr = args[1];
                console.log("[+] Connect called on socket: " + sockfd);
                
                // Parse sockaddr structure
                var family = Memory.readU16(addr);
                if (family == 2) { // AF_INET
                    var port = Memory.readU16(addr.add(2));
                    var ip = Memory.readU32(addr.add(4));
                    console.log("[+] Connecting to: " + 
                              ((ip >> 24) & 0xFF) + "." + 
                              ((ip >> 16) & 0xFF) + "." + 
                              ((ip >> 8) & 0xFF) + "." + 
                              (ip & 0xFF) + ":" + 
                              ((port >> 8) | (port << 8)) & 0xFFFF);
                }
            }
        });
    }
    
    // Hook SSL/TLS functions
    var ssl_write = libapp.getExportByName("SSL_write");
    if (ssl_write) {
        Interceptor.attach(ssl_write, {
            onEnter: function(args) {
                var ssl = args[0];
                var buf = args[1];
                var len = args[2];
                console.log("[+] SSL_write called with " + len + " bytes");
                console.log(hexdump(buf, { length: len.toInt32() }));
            }
        });
    }
    
    // Hook HTTP operations
    try {
        var http_client = Java.use("java.net.HttpURLConnection");
        http_client.getRequestMethod.implementation = function() {
            var method = this.getRequestMethod();
            console.log("[+] HTTP Request Method: " + method);
            return method;
        };
        
        http_client.getURL.implementation = function() {
            var url = this.getURL();
            console.log("[+] HTTP Request URL: " + url);
            return url;
        };
    } catch (e) {
        console.log("[-] HTTP hooking failed: " + e);
    }
    
    console.log("[+] All hooks installed successfully");
});

// Function to dump memory region
function dumpMemory(address, size) {
    console.log("[+] Dumping memory at 0x" + address.toString(16) + " (size: " + size + ")");
    console.log(hexdump(address, { length: size }));
}

// Function to find pattern in memory
function findPattern(pattern, base, size) {
    var results = [];
    for (var i = 0; i < size; i += 4) {
        var addr = base.add(i);
        try {
            var data = Memory.readByteArray(addr, pattern.length);
            if (data && Memory.readByteArray(addr, pattern.length).equals(pattern)) {
                results.push(addr);
            }
        } catch (e) {
            // Skip invalid memory
        }
    }
    return results;
}

console.log("[+] reFlutter Frida script ready");
`, fsg.platform, fsg.arch, baseAddress, baseAddress)

	return script
}

// FileUtilities provides file operation utilities
type FileUtilities struct{}

// NewFileUtilities creates a new file utilities instance
func NewFileUtilities() *FileUtilities {
	return &FileUtilities{}
}

// CreateDirectoryStructure creates necessary directory structure
func (fu *FileUtilities) CreateDirectoryStructure(basePath string) error {
	dirs := []string{
		"extracted",
		"patched",
		"output",
		"temp",
		"logs",
		"scripts",
	}

	for _, dir := range dirs {
		dirPath := filepath.Join(basePath, dir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dirPath, err)
		}
	}

	return nil
}

// CleanupTempFiles cleans up temporary files
func (fu *FileUtilities) CleanupTempFiles(basePath string) error {
	tempDir := filepath.Join(basePath, "temp")
	if _, err := os.Stat(tempDir); err == nil {
		return os.RemoveAll(tempDir)
	}
	return nil
}

// BackupFile creates a backup of a file
func (fu *FileUtilities) BackupFile(filePath string) error {
	backupPath := filePath + ".backup"

	sourceFile, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	backupFile, err := os.Create(backupPath)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer backupFile.Close()

	_, err = io.Copy(backupFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	return nil
}

// RestoreFile restores a file from backup
func (fu *FileUtilities) RestoreFile(filePath string) error {
	backupPath := filePath + ".backup"

	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file does not exist: %s", backupPath)
	}

	backupFile, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer backupFile.Close()

	targetFile, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create target file: %w", err)
	}
	defer targetFile.Close()

	_, err = io.Copy(targetFile, backupFile)
	if err != nil {
		return fmt.Errorf("failed to restore file: %w", err)
	}

	return nil
}
