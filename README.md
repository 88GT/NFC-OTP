# NFC-OTP Bridge

I had a need for a lightweight application that could read a YubiOTP code from a YubiKey over NFC.  Written in Go, this is what I came up with.

This is a Windows system tray application that monitors for a target application window to receive the focus, and then waits for the user to tap a YubiKey on an NFC reader.  The application will capture and parse the OTP, and then "type" it into the target window.  This is designed to work with the default YubiKey programming, which has a URI NDEF programmed from the factory.

# Configuration

The configuration is normally stored in the registry, under HKCU\Software\YubiNFC-OTP.  However, on first run, it will look for the existence of a config.ini file in the application directory.  If present, it will load those values into the registry.  If not present, it will use hard coded default values.

## Configuration Values:

* TargetWindowTitle = String array of values for the target window title.  If not sure, can use the diagnostic window in the app to help.  If set to ##ALL## then it will output to whatever window has the focus.
* Timeout           = Integer of seconds to wait before attempting another OTP read (default 10)
* ActiveWindowDelay = Integer in Milliseconds to delay when window is activated (default 300)
* KeystrokeDelay    = Integer in Milliseconds to delay the keystrokes when typing (default 10)
* OTPCaptureTimeout = Integer in Seconds to discard the unused OTP and reset the capture process (default 60)
* PortBinding       = Integer - This is a high range port simply used to prevent multiple instances from running (default 48237)
* ShowNotifications = Integer setting of 0,1,2 for showing the pop up notifications (default 1)
* EnableLogs        = Boolean True or false setting for diagnostic logging of activity (default True)
* MaxLogHistory     = Integer for Maximum number of lines to keep in the log, older lines will roll off (default 500)
* ReaderBlackList   = String array of values to blacklist invalid readers (eg, YubiKey plugged in to USB)
* ReaderWhiteList   = String array of values to whitelist or "prefer" specific readers

# Installation

Sample Installation powershell script is provided.  In order for the application to work across all applications (particularly target applications being run under other user contexts such as administrator) it is highly recommended that the compiled source code be digitally signed using a trusted certificate, and then it is necessary to place the signed executable in the "C:\Program Files" directory.

# Usage

Once the application is launched, the icon will appear in the system tray.  Right click to show a menu that allows access to the diagnostic screen.  The diagnostic screen will display the active window, as well as various diagnostic messages useful for testing purposes.  These messages can be exported to a file if necessary.  The menu also has an "about" option and the "exit" option.

# Version History
<ins>0.87</ins>
Added Feature: OTP Timeout Value - Discard unused OTP and reset capture process
Added Feature: Add support for multiple windows to trigger OTP capture (Changed Target Window Title to a string array)
Added Feature: Add support for OTP input immediately into active window (no scanning) (Set ##ALL## in Target Window Title config)
Added Feature: NFC Reader Blacklist (Block "fake" readers)
Added Feature: NFC Reader Whitelist (Look for specific readers)
Added Feature: Pause mode - pause scanning for active windows / OTP capture (Double click tray icon to toggle)
Improvement: Instead of pop up notifications being on or off, set additional granularity (0=Off, 1=Success Only, 2=All)

<ins>0.80</ins>
Initial self signed compiled release
Bug fixes and performance enhancements

<ins>0.76</ins>
Initial Internal Release