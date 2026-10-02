package main

import (
	"bufio"
	_ "embed" // Required for go:embed
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/ebfe/scard"
	"github.com/gen2brain/beeep"
	"github.com/gogpu/systray"
	"golang.org/x/sys/windows/registry"
)

// YubiOTP NFC Middleware - Windows System Tray Implementation
// ------------------------
// (c)2026 - Beau Anderson
// ------------------------
//
// Beta - Version 0.87 - 10/02/2026
//

// This is for the tray icon of the program
// Embed the image file into the binary as a byte slice
//
// Note that the command to embed the icon is intentionally commented
// this is correct syntax
//
//go:embed tray.png
var iconNormal []byte

//go:embed traypaused.png
var iconPaused []byte

// Global state for diagnostics logging
var (
	logMutex       sync.Mutex
	logHistory     []string
	logsEnabled    bool
	maxLogLength   int
	appPaused      bool
	diagHwnd       uintptr // Handle to the diagnostics window
	activeEditHwnd uintptr // Pointer to the active edit box
)

// Windows API Definitions
var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procCreateWindowExW     = user32.NewProc("CreateWindowExW")
	procDefWindowProcW      = user32.NewProc("DefWindowProcW")
	procRegisterClassExW    = user32.NewProc("RegisterClassExW")
	procShowWindow          = user32.NewProc("ShowWindow")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procGetMessageW         = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessageW    = user32.NewProc("DispatchMessageW")
	procSendMessageW        = user32.NewProc("SendMessageW")
	procGetModuleHandleW    = kernel32.NewProc("GetModuleHandleW")
	procMessageBoxW         = user32.NewProc("MessageBoxW")
	procGetForegroundWindow = user32.NewProc("GetForegroundWindow")
	procGetWindowTextW      = user32.NewProc("GetWindowTextW")
	procSendInput           = user32.NewProc("SendInput")
)

const (
	// Control IDs
	ID_BTN_EXPORT   = 1001
	ID_BTN_OPEN_DIR = 1002
	ID_BTN_CLOSE    = 1003

	// Windows Related Stuff
	WS_OVERLAPPED  = 0x00000000
	WS_CAPTION     = 0x00C00000
	WS_SYSMENU     = 0x00080000
	WS_MINIMIZEBOX = 0x00020000
	WS_VISIBLE     = 0x10000000
	WS_CHILD       = 0x40000000
	WS_TABSTOP     = 0x00010000
	WS_VSCROLL     = 0x00200000
	BS_PUSHBUTTON  = 0x00000000
	ES_MULTILINE   = 0x0004
	ES_AUTOVSCROLL = 0x0040
	ES_READONLY    = 0x0800
	EM_SETSEL      = 0x00B1
	EM_REPLACESEL  = 0x00C2
	WM_COMMAND     = 0x0111
	WM_CLOSE       = 0x0010
	WM_DESTROY     = 0x0002
	SW_SHOWNORMAL  = 1
	SW_HIDE        = 0

	//Notification Related
	NIM_ADD    = 0x00000000
	NIM_MODIFY = 0x00000001
	NIM_DELETE = 0x00000002
	NIF_INFO   = 0x00000010
	NIIF_INFO  = 0x00000001

	//For emulating typing in the OTP
	inputKeyboard    = 1
	keyeventfUnicode = 0x0004
	keyeventfKeyup   = 0x0002
	vkReturn         = 0x0D

	// Registry key path under HKEY_CURRENT_USER
	regKeyPath = `Software\YubiOTP-NFC`

	// ModHex valid character set
	modhexChars = "cbdefghijklnrtuv"
)

// Structures
type KEYBDINPUT struct {
	Vk        uint16
	Scan      uint16
	Flags     uint32
	Time      uint32
	ExtraInfo uintptr
}

type INPUT struct {
	Type uint32
	Ki   KEYBDINPUT
	_    [8]byte // Padding for 64-bit architecture alignment
}

type WNDCLASSEX struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type MSG struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

// Configuration
type Config struct {
	TargetWindowTitle []string // Titles of target windows.  If set to ##ALL## then it will output to whatever window has the focus
	Timeout           int      // seconds to wait before attempting another OTP read (default 20)
	ActiveWindowDelay int      // Milliseconds to delay when window is activated (default 300)
	KeystrokeDelay    int      // Milliseconds to delay the keystrokes when typing (default 10)
	OTPCaptureTimeout int      // Timeout value for discarding the unused OTP and resetting the capture process (default 60)
	PortBinding       int      // This is a high range port simply used to prevent multiple instances from running (default 48237)
	ShowNotifications int      // 0, 1, or 2 setting for showing the pop up notifications (default 1 - Suppress Fail Messages)
	EnableLogs        bool     // True or false setting for diagnostic logging of activity (default True)
	MaxLogHistory     int      // Maximum number of lines to keep in the log, older lines will roll off (Default 500)
	ReaderBlackList   []string // Array of strings that are NFC reader names that will be blacklisted
	ReaderWhiteList   []string // Array of strings that are NFC reader names that will be whitelisted
}

// APDU Commands for reading the YubiKey NDEF
var (
	selectNDEFApp  = []byte{0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01}
	selectNDEFFile = []byte{0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04}
	readBinary     = []byte{0x00, 0xB0, 0x00, 0x00, 0x00}
)

// Functions:
//
// getActiveWindowTitle queries Windows for the currently focused window title.
func getActiveWindowTitle() string {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return ""
	}

	b := make([]uint16, 256)
	procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	return syscall.UTF16ToString(b)
}

// emulateTyping simulates keyboard input for a string and presses 'Enter'.
func emulateTyping(text string, cfg *Config) {
	for _, ch := range text {
		// Key down
		inputDown := INPUT{
			Type: inputKeyboard,
			Ki: KEYBDINPUT{
				Scan:  uint16(ch),
				Flags: keyeventfUnicode,
			},
		}
		// Key up
		inputUp := INPUT{
			Type: inputKeyboard,
			Ki: KEYBDINPUT{
				Scan:  uint16(ch),
				Flags: keyeventfUnicode | keyeventfKeyup,
			},
		}

		procSendInput.Call(1, uintptr(unsafe.Pointer(&inputDown)), unsafe.Sizeof(inputDown))
		procSendInput.Call(1, uintptr(unsafe.Pointer(&inputUp)), unsafe.Sizeof(inputUp))
		time.Sleep(time.Duration(cfg.KeystrokeDelay) * time.Millisecond)
	}

	// Press Enter key
	enterDown := INPUT{
		Type: inputKeyboard,
		Ki:   KEYBDINPUT{Vk: vkReturn},
	}
	enterUp := INPUT{
		Type: inputKeyboard,
		Ki:   KEYBDINPUT{Vk: vkReturn, Flags: keyeventfKeyup},
	}
	procSendInput.Call(1, uintptr(unsafe.Pointer(&enterDown)), unsafe.Sizeof(enterDown))
	procSendInput.Call(1, uintptr(unsafe.Pointer(&enterUp)), unsafe.Sizeof(enterUp))
}

// --- SmartCard / NFC Logic ---
func findPICCReader(ctx *scard.Context, cfg *Config) (string, error) {
	readers, err := ctx.ListReaders()
	if err != nil || len(readers) == 0 {
		LogDiag("ERROR: No readers found")
		return "", fmt.Errorf("ERROR: No readers found")
	}

	// Log the number of readers found - so we can compare later to how many are being removed
	LogDiag("Found %d readers", len(readers))

	// Prefer contactless/PICC interface explicitly else check for a non-SAM interface
	// This loop needs to look through all the list of readers found to first return a PICC or SAM reader
	for _, r := range readers {
		name := strings.ToUpper(r)
		if strings.Contains(name, "PICC") || (strings.Contains(name, " CL ") && !strings.Contains(name, "SAM")) {
			LogDiag("PICC/SAM Reader Found: %s", r)
			return r, nil
		}
	}

	// Next, this code is run if so far we have a list of readers, but none match "PICC", " CL ", or "SAM" in the name
	// So now we need to return whatever we have left, but we need to remove any readers that are on the ReaderBlackList
	// NOTE:  IF a yubikey is plugged into USB, it will show up as a reader, so the blacklist should always have FIDO on it
	for i := 0; i < len(readers); i++ {
		r := readers[i]
		name := strings.ToLower(r)
		matched, _ := checkForMatch(cfg.ReaderBlackList, name)
		if matched {
			LogDiag("Removing Invalid Reader: %s", r)
			// Perform the removal
			readers[i] = readers[len(readers)-1]
			readers = readers[:len(readers)-1]
			i--
		}
	}

	// Because the blacklist check might have removed the only reader we found, we need to make sure that
	// we are checking to see if the list is empty, and if so, returning "No readers found"
	if len(readers) == 0 {
		LogDiag("ERROR: No readers found")
		return "", fmt.Errorf("ERROR: No readers found")
	}

	// We need to check for the existence of Whitelisted Readers
	// Right now it will return the first whitelisted reader that is found
	for i := 0; i < len(readers); i++ {
		r := readers[i]
		name := strings.ToLower(r)
		matched, _ := checkForMatch(cfg.ReaderWhiteList, name)
		if matched {
			LogDiag("Using Whitelisted Reader: %s", r)
			return readers[i], nil
		}
	}

	//  If there are any remaining readers left, lets log and return the first one...
	for i := 0; i < len(readers); i++ {
		LogDiag("Allowed NFC Reader Found: %s", readers[i])
	}

	// Known limitation - it is only returning the first allowed reader it finds - need to improve this to return all readers
	return readers[0], nil
}

// Check for the existence of the Modhex characters
func isModhex(s string) bool {
	for _, r := range s {
		if !strings.ContainsRune(modhexChars, r) {
			return false
		}
	}
	return true
}

// Function to read the OTP (Or at least attempt to!)
func readOTPOnce(ctx *scard.Context, readerName string, cfg *Config) (string, error) {
	// Block until a card/tap is present on the specified reader
	var card *scard.Card
	var err error

	for {
		// Connect exclusively to handle the tap immediately
		card, err = ctx.Connect(readerName, scard.ShareExclusive, scard.ProtocolT1)
		if err == nil {
			break
		}
		time.Sleep(time.Duration(cfg.ActiveWindowDelay) * time.Millisecond)
	}

	// Ensure cleanup right away so reader isn't held open
	defer card.Disconnect(scard.LeaveCard)

	status, err := card.Status()
	if err == nil {
		LogDiag(" [Connected via T1] ATR: %X", status.Atr)
	}

	var data []byte

	// Perform NDEF Read Sequence with single retry on 0x6D00 failure
	for readAttempt := 1; readAttempt <= 2; readAttempt++ {
		ok := true

		// Step 1: Select NDEF Application
		data, err = card.Transmit(selectNDEFApp)
		if err != nil || len(data) < 2 || data[len(data)-2] != 0x90 || data[len(data)-1] != 0x00 {
			ok = false
		}

		if ok {
			// Step 2: Select NDEF File
			data, err = card.Transmit(selectNDEFFile)
			if err != nil || len(data) < 2 || data[len(data)-2] != 0x90 || data[len(data)-1] != 0x00 {
				ok = false
			}
		}

		if ok {
			// Step 3: Read NDEF File
			data, err = card.Transmit(readBinary)
			if err != nil || len(data) < 2 || data[len(data)-2] != 0x90 || data[len(data)-1] != 0x00 {
				ok = false
			}
		}

		if ok {
			break
		}

		if readAttempt == 1 {
			time.Sleep((time.Duration(cfg.ActiveWindowDelay) * time.Millisecond) * 2)
		} else {
			LogDiag("ERROR: NDEF read sequence failed")
			return "", fmt.Errorf("NDEF read sequence failed")
		}
	}

	// Filter printable ASCII bytes
	var builder strings.Builder
	for _, b := range data[:len(data)-2] { // exclude SW bytes
		if b >= 32 && b <= 126 {
			builder.WriteByte(b)
		}
	}
	payload := builder.String()
	LogDiag("  Raw payload: %q", payload)

	candidate := payload
	if strings.Contains(payload, "#") {
		parts := strings.Split(payload, "#")
		candidate = parts[len(parts)-1]
	}
	candidate = strings.TrimSpace(candidate)

	if len(candidate) >= 32 && len(candidate) <= 48 && isModhex(candidate) {
		LogDiag("  Parsed OTP (%d chars): %s", len(candidate), candidate)
		return candidate, nil
	}

	LogDiag("ERROR: Payload did not contain a valid YubiOTP")
	return "", fmt.Errorf("payload did not contain a valid modhex OTP")
}

// This function checks to see if the app can bind to a port on localhost
// This is to be able to prevent multiple instances of the app from being run at the same time
func BindToLocalhost(port int) (net.Listener, error) {
	address := fmt.Sprintf("127.0.0.1:%d", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		ShowMessageBox("Warning!", "App is already running, or "+address+" is unavailable")
		os.Exit(1)
	}
	return listener, nil
}

// ShowMessageBox displays a native Win32 message box
func ShowMessageBox(title, message string) {
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	messagePtr, _ := syscall.UTF16PtrFromString(message)

	// 0x40 = Information icon, 0x0 = OK button
	procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(messagePtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		0x00000040,
	)
}

// LogDiag can be called from any function in order to record logs
func LogDiag(format string, args ...interface{}) {
	// If logs are enabled, store in historical memory (up to the configured limit)
	if logsEnabled {
		logMutex.Lock()
		defer logMutex.Unlock()

		var message string

		if len(args) > 0 {
			message = fmt.Sprintf(format, args...)
		} else {
			message = format
		}

		formattedText := fmt.Sprintf("[%s] %s\r\n", time.Now().Format("15:04:05"), message)

		// Check the current length against the max length
		if len(logHistory) >= maxLogLength {
			// Drop the oldest entry (index 0) and shift everything left
			logHistory = logHistory[1:]
		}

		// write the log entry
		logHistory = append(logHistory, formattedText)

		// If the UI window is currently open, print to it immediately
		if activeEditHwnd != 0 {
			appendRawTextToEdit(activeEditHwnd, formattedText)
		}
	}
}

// ShowDiagnosticsWindow creates or shows the native Win32 window
func ShowDiagnosticsWindow() {
	logMutex.Lock()
	// If the window is already created, just unhide and bring it to the front
	if diagHwnd != 0 {
		procShowWindow.Call(diagHwnd, SW_SHOWNORMAL)
		procSetForegroundWindow.Call(diagHwnd)
		logMutex.Unlock()
		return
	}
	logMutex.Unlock()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	instance, _, _ := procGetModuleHandleW.Call(0)
	className, _ := syscall.UTF16PtrFromString("DiagnosticsWindowClass")

	var wndClass WNDCLASSEX
	wndClass.Size = uint32(unsafe.Sizeof(wndClass))
	wndClass.WndProc = syscall.NewCallback(wndProc)
	wndClass.Instance = instance
	wndClass.ClassName = className
	wndClass.Background = 5 // COLOR_WINDOW

	// Register window class (Ignore if already registered)
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wndClass)))

	titlePtr, _ := syscall.UTF16PtrFromString("Diagnostics Output")

	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(titlePtr)),
		WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
		100, 100, 640, 430, // Increased height slightly for button area
		0, 0, instance, 0,
	)

	if hwnd == 0 {
		return
	}

	// Create Multi-line Edit box inside window (Height is 320 to leave room for button)
	editClass, _ := syscall.UTF16PtrFromString("EDIT")
	editHwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(editClass)),
		0,
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY,
		10, 10, 600, 320,
		hwnd, 0, instance, 0,
	)

	// Create "Export Logs" Button
	buttonClass, _ := syscall.UTF16PtrFromString("BUTTON")
	buttonText, _ := syscall.UTF16PtrFromString("Export Logs")
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(buttonClass)),
		uintptr(unsafe.Pointer(buttonText)),
		WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON|WS_TABSTOP,
		20, 345, 120, 30, // Placed at the bottom right
		hwnd, uintptr(ID_BTN_EXPORT), instance, 0,
	)

	//Create "Open Folder" Button - For easy nav to the log file
	btnOpenDirText, _ := syscall.UTF16PtrFromString("Open Folder")
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(buttonClass)),
		uintptr(unsafe.Pointer(btnOpenDirText)),
		WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON|WS_TABSTOP,
		180, 345, 120, 30, // Positioned to the left of the "Export Logs" button
		hwnd, uintptr(ID_BTN_OPEN_DIR), instance, 0,
	)

	//Create a "Close" Button (Rightmost)
	btnCloseText, _ := syscall.UTF16PtrFromString("Close")
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(buttonClass)),
		uintptr(unsafe.Pointer(btnCloseText)),
		WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON|WS_TABSTOP,
		485, 345, 120, 30,
		hwnd, uintptr(ID_BTN_CLOSE), instance, 0,
	)

	// Register handles globally and populate log history
	logMutex.Lock()
	diagHwnd = hwnd
	activeEditHwnd = editHwnd
	for _, entry := range logHistory {
		appendRawTextToEdit(editHwnd, entry)
	}
	logMutex.Unlock()

	procShowWindow.Call(hwnd, SW_SHOWNORMAL)

	// Message loop
	var msg MSG
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if ret == 0 || ret == ^uintptr(0) {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

// Low-level helper to write text into the Win32 edit control
func appendRawTextToEdit(editHwnd uintptr, text string) {
	textPtr, _ := syscall.UTF16PtrFromString(text)
	procSendMessageW.Call(editHwnd, EM_SETSEL, ^uintptr(0), ^uintptr(0))
	procSendMessageW.Call(editHwnd, EM_REPLACESEL, 0, uintptr(unsafe.Pointer(textPtr)))
}

// Export log history to a text file in the application folder
func exportLogsToFile() {
	logMutex.Lock()
	content := strings.Join(logHistory, "")
	logMutex.Unlock()

	fileName := fmt.Sprintf("diagnostics_%s.log", time.Now().Format("20060102_150405"))
	err := os.WriteFile(fileName, []byte(content), 0644)

	var titlePtr, msgPtr *uint16
	if err != nil {
		titlePtr, _ = syscall.UTF16PtrFromString("Export Error")
		msgPtr, _ = syscall.UTF16PtrFromString(fmt.Sprintf("Failed to save log file: %v", err))
	} else {
		titlePtr, _ = syscall.UTF16PtrFromString("Export Successful")
		msgPtr, _ = syscall.UTF16PtrFromString(fmt.Sprintf("Logs exported successfully to:\n%s", fileName))
	}

	// 0x40 = Information Icon / OK Button
	procMessageBoxW.Call(
		diagHwnd,
		uintptr(unsafe.Pointer(msgPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		0x00000040,
	)
}

// This runs when the "Open Folder" button is clicked - Opens Explorer to app folder
func openAppDirectory() {
	// Get path of the running executable
	exePath, err := os.Executable()
	if err != nil {
		// Fallback to current working directory if executable path fails
		exePath, _ = os.Getwd()
	}

	dir := filepath.Dir(exePath)

	// Open Windows Explorer targeting the executable's directory
	exec.Command("explorer", dir).Start()
}

// Window procedure callback - This handles the "clicking" of the diagnostic buttons
func wndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case WM_COMMAND:
		// Check if the low word of wParam matches our Button ID
		if wParam&0xFFFF == ID_BTN_EXPORT {
			exportLogsToFile()
			return 0
		}
		if wParam&0xFFFF == ID_BTN_OPEN_DIR {
			openAppDirectory()
			return 0
		}
		if wParam&0xFFFF == ID_BTN_CLOSE {
			// Post a WM_CLOSE message to trigger standard window closing
			procShowWindow.Call(hwnd, SW_HIDE)
		}
	case WM_CLOSE:
		// Intercept Close: Hide window instead of destroying it
		procShowWindow.Call(hwnd, SW_HIDE)
		return 0
	case WM_DESTROY:
		return 0
	}
	res, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return res
}

// loadConfig orchestrates the Registry -> INI fallback logic
func loadConfig() (*Config, error) {
	// 1. Try reading from Registry first
	cfg, err := readFromRegistry()
	if err == nil {
		LogDiag("[Config Source]: Loaded from Windows Registry (HKCU\\Software\\YubiOTP-NFC)")
		return cfg, nil
	}

	// 2. Fallback: Read from INI file using standard library
	LogDiag("[Config Source]: Registry key missing. Reading from config.ini...")
	cfg, err = parseINIFile("config.ini")
	if err != nil {
		LogDiag("Could not read INI File!")
		return nil, fmt.Errorf("could not read INI file: %w", err)
	}

	// 3. Save to Registry so future runs skip the INI file
	if err := saveToRegistry(cfg); err != nil {
		LogDiag("Warning: Failed to write to registry: %v\n", err)
	} else {
		LogDiag("[Config Action]: Saved INI values to HKCU\\Software\\YubiOTP-NFC")
	}

	return cfg, nil
}

// readFromRegistry attempts to read settings from the configured registry path
func readFromRegistry() (*Config, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, regKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	title, _, err := k.GetStringsValue("TargetWindowTitle")
	if err != nil {
		return nil, err
	}

	timeoutVal, _, err := k.GetIntegerValue("Timeout")
	if err != nil {
		return nil, err
	}

	ActiveWindowDelayVal, _, err := k.GetIntegerValue("ActiveWindowDelay")
	if err != nil {
		return nil, err
	}

	KeystrokeDelayVal, _, err := k.GetIntegerValue("KeystrokeDelay")
	if err != nil {
		return nil, err
	}

	OTPCaptureTimeoutVal, _, err := k.GetIntegerValue("OTPCaptureTimeout")
	if err != nil {
		return nil, err
	}

	PortBindingVal, _, err := k.GetIntegerValue("PortBinding")
	if err != nil {
		return nil, err
	}

	ShowNotificationsVal, _, err := k.GetIntegerValue("ShowNotifications")
	if err != nil {
		return nil, err
	}

	EnableLogsVal, _, err := k.GetStringValue("EnableLogs")
	if err != nil {
		return nil, err
	}

	MaxLogHistoryVal, _, err := k.GetIntegerValue("MaxLogHistory")
	if err != nil {
		return nil, err
	}

	ReaderBlackListVal, _, err := k.GetStringsValue("ReaderBlackList")
	if err != nil {
		return nil, err
	}

	ReaderWhiteListVal, _, err := k.GetStringsValue("ReaderWhiteList")
	if err != nil {
		return nil, err
	}

	EnableLogsBool, err := strconv.ParseBool(EnableLogsVal)

	return &Config{
		TargetWindowTitle: []string(title),
		Timeout:           int(timeoutVal),
		ActiveWindowDelay: int(ActiveWindowDelayVal),
		KeystrokeDelay:    int(KeystrokeDelayVal),
		OTPCaptureTimeout: int(OTPCaptureTimeoutVal),
		PortBinding:       int(PortBindingVal),
		ShowNotifications: int(ShowNotificationsVal),
		EnableLogs:        bool(EnableLogsBool),
		MaxLogHistory:     int(MaxLogHistoryVal),
		ReaderBlackList:   []string(ReaderBlackListVal),
		ReaderWhiteList:   []string(ReaderWhiteListVal),
	}, nil
}

// parseINIFile reads and parses key-value pairs line by line
func parseINIFile(filepath string) (*Config, error) {
	// Default fallback values in case install is missing the INI file or it is malformed
	cfg := &Config{
		TargetWindowTitle: []string{"Notepad"},
		Timeout:           10,
		ActiveWindowDelay: 300,
		KeystrokeDelay:    10,
		OTPCaptureTimeout: 60,
		PortBinding:       48237,
		ShowNotifications: 1,
		EnableLogs:        true,
		MaxLogHistory:     500,
		ReaderBlackList:   []string{"BROADCOM", "FIDO"},
		ReaderWhiteList:   []string{"ACS"},
	}

	// Open the file or fall back to the defaults above if the file is missing
	file, err := os.Open(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			LogDiag("Config.ini not found in application folder.  Using Hardcoded Values")
			return cfg, nil
		}
		return cfg, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines or section headers like [Settings]
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}

		// Split on the first '=' character
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "TargetWindowTitle":
			cfg.TargetWindowTitle = strings.Split(string(val), ",")
		case "Timeout":
			if timeoutInt, err := strconv.Atoi(val); err == nil {
				cfg.Timeout = timeoutInt
			}
		case "ActiveWindowDelay":
			if ActiveWindowDelayInt, err := strconv.Atoi(val); err == nil {
				cfg.ActiveWindowDelay = ActiveWindowDelayInt
			}
		case "KeystrokeDelay":
			if KeystrokeDelayInt, err := strconv.Atoi(val); err == nil {
				cfg.KeystrokeDelay = KeystrokeDelayInt
			}
		case "OTPCaptureTimeout":
			if OTPCaptureTimeoutInt, err := strconv.Atoi(val); err == nil {
				cfg.OTPCaptureTimeout = OTPCaptureTimeoutInt
			}
		case "PortBinding":
			if PortBindingInt, err := strconv.Atoi(val); err == nil {
				cfg.PortBinding = PortBindingInt
			}
		case "ShowNotifications":
			if ShowNotificationsInt, err := strconv.Atoi(val); err == nil {
				cfg.ShowNotifications = ShowNotificationsInt
			}
		case "EnableLogs":
			EnableLogsStr := val
			EnableLogsBool, err := strconv.ParseBool(EnableLogsStr)
			if err != nil {
				LogDiag("Value for EnableLogs is not true or false!  Setting to true")
				EnableLogsBool = true
			}
			cfg.EnableLogs = EnableLogsBool
		case "MaxLogHistory":
			if MaxLogHistoryInt, err := strconv.Atoi(val); err == nil {
				cfg.MaxLogHistory = MaxLogHistoryInt
			}
		case "ReaderBlackList":
			cfg.ReaderBlackList = strings.Split(string(val), ",")
		case "ReaderWhiteList":
			cfg.ReaderWhiteList = strings.Split(string(val), ",")
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// saveToRegistry stores values under the registry path defined in the declarations
func saveToRegistry(cfg *Config) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, regKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if err := k.SetStringsValue("TargetWindowTitle", cfg.TargetWindowTitle); err != nil {
		return err
	}

	if err := k.SetDWordValue("Timeout", uint32(cfg.Timeout)); err != nil {
		return err
	}

	if err := k.SetDWordValue("ActiveWindowDelay", uint32(cfg.ActiveWindowDelay)); err != nil {
		return err
	}

	if err := k.SetDWordValue("KeystrokeDelay", uint32(cfg.KeystrokeDelay)); err != nil {
		return err
	}

	if err := k.SetDWordValue("OTPCaptureTimeout", uint32(cfg.OTPCaptureTimeout)); err != nil {
		return err
	}

	if err := k.SetDWordValue("PortBinding", uint32(cfg.PortBinding)); err != nil {
		return err
	}

	if err := k.SetDWordValue("ShowNotifications", uint32(cfg.ShowNotifications)); err != nil {
		return err
	}

	if err := k.SetStringValue("EnableLogs", strconv.FormatBool(cfg.EnableLogs)); err != nil {
		return err
	}

	if err := k.SetDWordValue("MaxLogHistory", uint32(cfg.MaxLogHistory)); err != nil {
		return err
	}

	if err := k.SetStringsValue("ReaderBlackList", cfg.ReaderBlackList); err != nil {
		return err
	}

	if err := k.SetStringsValue("ReaderWhiteList", cfg.ReaderWhiteList); err != nil {
		return err
	}

	return nil
}

// Function to check if the title window matches the configuration of title windows, or if ##ALL## is set
func checkForMatch(configValues []string, currentValue string) (matched bool, allMode bool) {
	lowerCaseVal := strings.ToLower(currentValue)

	for _, checker := range configValues {
		if checker == "##ALL##" {
			return true, true
		}
		if strings.Contains(lowerCaseVal, strings.ToLower(checker)) {
			matched = true
		}
	}
	return matched, false
}

// runNFCScanner handles window focus checking and NFC card reading asynchronously.
func runNFCScanner(ctx *scard.Context, cfg *Config) {
	defer ctx.Release()
	beeep.AppName = "YubiOTP NFC Bridge"

	//  Save the initial window so that we can log the switch window events
	previousTitle := getActiveWindowTitle()
	LogDiag("Monitoring active windows... '%s' has the focus.", previousTitle)

	for {
		if !appPaused {
			currentTitle := getActiveWindowTitle()

			if currentTitle != previousTitle {
				LogDiag("Monitoring active windows... '%s' has the focus.", currentTitle)
				previousTitle = currentTitle
			}

			matched, isAll := checkForMatch(cfg.TargetWindowTitle, currentTitle)

			if matched {
				if isAll {
					LogDiag("[!] System Set to match ALL windows with ##ALL## parameter")
				} else {
					LogDiag("[!] Match Found: '%s'", currentTitle)
				}

				readerName, err := findPICCReader(ctx, cfg)
				if err != nil {
					LogDiag("No PC/SC readers found. Plug in reader and restart.")
					// Show Pop up notification, if enabled
					if cfg.ShowNotifications >= 2 {
						// Use Beeep to show a toast notification
						notify := beeep.Notify("YubiOTP NFC", "No PC/SC readers found. Plug in reader and retry.", iconNormal)
						if notify != nil {
							LogDiag("Failed to show notification: No PC/SC readers found.")
						}
					}
					// Prevent heavy loop hammering when reader is unplugged by 30x the active window delay (so 9 seconds by default)
					time.Sleep((time.Duration(cfg.ActiveWindowDelay) * time.Millisecond) * 30)
					continue
				}

				LogDiag("Using reader interface: %s", readerName)
				LogDiag("Waiting for tap...")

				otp, err := readOTPOnce(ctx, readerName, cfg)
				if err != nil {
					LogDiag("Read failed: %v -- tap again.", err)
					// Show Pop up notification, if enabled
					if cfg.ShowNotifications >= 2 {
						// Use Beeep to show a toast notification
						notify := beeep.Notify("YubiOTP NFC", "Read failed: Try a longer tap", iconNormal)
						if notify != nil {
							LogDiag("Failed to show notification: Read failed.")
						}
					}
					// Double the time duration for testing - can change multiplier as needed
					time.Sleep((time.Duration(cfg.ActiveWindowDelay) * time.Millisecond) * 2)
					continue
				}

				LogDiag("OTP captured. Checking that target window is still active before typing...")

				// This makes a counter value by dividing the active window delay into the OTP timeout value.  EG 300 ms into 60 seconds is 200
				// The reset counter will be incremented until it gets to the divider value and this will trigger the timeout
				divider := (cfg.OTPCaptureTimeout * 1000) / cfg.ActiveWindowDelay
				resetCounter := 0

				// Active window confirmation check loop (makes sure active window is a match before typing OTP)
				for {
					title := getActiveWindowTitle()

					matched, isAll := checkForMatch(cfg.TargetWindowTitle, title)

					if matched {
						if isAll {
							LogDiag("[!] System Set to match ALL windows with ##ALL## parameter")
							LogDiag("Typing OTP into '%s'", title)
						} else {
							LogDiag("Active Window Matches. Typing OTP into '%s'", title)
						}

						time.Sleep(time.Duration(cfg.ActiveWindowDelay) * time.Millisecond)
						emulateTyping(otp, cfg)

						// Show Pop up notification, if enabled
						if cfg.ShowNotifications >= 1 {
							// Use Beeep to show a toast notification
							notify := beeep.Notify("YubiOTP NFC", "OTP Captured Successfully", iconNormal)
							if notify != nil {
								LogDiag("Failed to show notification: OTP Captured Successfully")
							}
						}

						// Clear the otp variable
						otp = "###########"

						// Countdown loop
						for countdown := cfg.Timeout; countdown > 0; countdown-- {
							LogDiag("Re-Scanning OTP in '%d' seconds", countdown)
							time.Sleep(1 * time.Second)
						}
						LogDiag("Task complete. Going back to scanning for OTP.")
						break
					}
					time.Sleep(time.Duration(cfg.ActiveWindowDelay) * time.Millisecond)
					resetCounter++
					if resetCounter%10 == 0 {
						LogDiag("OTP Reset Counter is at '%d' out of '%d' Total", resetCounter, divider)
					}
					if resetCounter >= divider {
						LogDiag("OTP Reset Counter reached in '%d' seconds", cfg.OTPCaptureTimeout)
						// Clear the otp variable
						otp = "###########"
						// Log the clear action
						LogDiag("OTP Cleared - Resetting Capture Process")
						// exit the loop
						break
					}
				}
			}
			time.Sleep(time.Duration(cfg.ActiveWindowDelay) * time.Millisecond)
		}
	}
}

// Main function - initializes log file, loads configuration, instantiates the tray icon
// and starts scanning for the active window
func main() {
	// Temporarily set logs to be Enabled with max length 100
	logsEnabled = true
	maxLogLength = 100
	appPaused = false

	// Start a new diagnostic message log
	LogDiag("-----  YubiOTP NFC Keyboard Wedge System Tray App (0.87 beta) -----")
	LogDiag("-----------------------------------------------------------------------------------------------------------")

	// Load config values and report their values in the log file
	cfg, err := loadConfig()
	if err != nil {
		LogDiag("Failed to load configuration: %v", err)
	} else if !cfg.EnableLogs {
		LogDiag("Logs have been disabled by configuration setting")
	} else {
		LogDiag("Configuration Loaded Successfully!")
		LogDiag("TargetWindowTitle: %s", cfg.TargetWindowTitle)
		LogDiag("Timeout: %d seconds", cfg.Timeout)
		LogDiag("ActiveWindowDelay: %d milliseconds", cfg.ActiveWindowDelay)
		LogDiag("KeystrokeDelay: %d milliseconds", cfg.KeystrokeDelay)
		LogDiag("OTPCaptureTimeout: %d seconds", cfg.OTPCaptureTimeout)
		LogDiag("PortBinding: %d", cfg.PortBinding)
		LogDiag("ShowNotifications: %d", cfg.ShowNotifications)
		LogDiag("EnableLogs: %t", cfg.EnableLogs)
		LogDiag("MaxLogHistory: %d", cfg.MaxLogHistory)
		LogDiag("ReaderBlackList: %s", strings.Join(cfg.ReaderBlackList, ","))
		LogDiag("ReaderWhiteList: %s", strings.Join(cfg.ReaderWhiteList, ","))
	}
	LogDiag("-----------------------------------------------------------------------------------------------------------")
	// update these global vars so I don't have to pass them on every call to LogDiag
	logsEnabled = cfg.EnableLogs
	maxLogLength = cfg.MaxLogHistory

	// Try to bind to a configurable port on localhost to make sure no other instance is running
	TCPListener, err := BindToLocalhost(cfg.PortBinding)

	// If another instance is running - we should never return from the above func
	// However, go is saying we should do another check here just in case.
	// Then we need to eventually release the port.  This line releases the port when main exits
	if err != nil {
		ShowMessageBox("Warning!", "App is already running, or port "+strconv.Itoa(cfg.PortBinding)+" is unavailable")
	}
	defer TCPListener.Close()

	// Create a new System Tray Application Instance
	tray := systray.New()

	// Build context menu
	menu := systray.NewMenu()

	menu.Add("Diagnostics", func() {
		go ShowDiagnosticsWindow()
	})

	menu.Add("About", func() {
		ShowMessageBox("About", "YubiOTP NFC Middleware v 0.87 - 10/02/2026")
	})

	menu.AddSeparator()

	menu.Add("Quit", func() {
		tray.Remove()
		os.Exit(0)
	})

	// Set icon
	tray.SetIcon(iconNormal)
	tray.SetTooltip("YubiOTP NFC Bridge")
	tray.SetMenu(menu)

	tray.OnDoubleClick(func() {
		appPaused = !appPaused
		if appPaused {
			tray.SetIcon(iconPaused)
			LogDiag("Application Pause State: %t", appPaused)
		} else {
			tray.SetIcon(iconNormal)
			LogDiag("Application Pause State: %t", appPaused)
		}
	})

	ctx, err := scard.EstablishContext()
	if err != nil {
		LogDiag("Failed to establish PC/SC Context: %v", err)
		// Option: Show notification or alert here if initialization fails
	} else {
		// Launch the scanner loop as a non-blocking Goroutine
		go runNFCScanner(ctx, cfg)
	}

	// Add monitoring log message
	LogDiag("Monitoring active windows... Waiting for '%s' to gain focus.", cfg.TargetWindowTitle)

	// Show and start system tray loop (Blocks the main OS thread)
	tray.Show()
	tray.Run()
}
