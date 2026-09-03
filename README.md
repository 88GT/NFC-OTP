# NFC-OTP Bridge

I had a need for a lightweight application that could read a YubiOTP code from a YubiKey over NFC.  Written in Go, this is what I came up with.

This is a Windows system tray application that monitors for a target application window to receive the focus, and then waits for the user to tap a YubiKey on an NFC reader.  The application will capture and parse the OTP, and then "type" it into the target window.  This is designed to work with the default YubiKey programming, which has a URI NDEF programmed from the factory.

# Configuration

The configuration is normally stored in the registry, under HKCU\Software\YubiNFC-OTP.  However, on first run, it will look for the existence of a config.ini file in the application directory.  If present, it will load those values into the registry.  If not present, it will use hard coded default values.

Configuration Values:
---------------------
TargetWindowTitle  // String value of the target window title.  If not sure, can use the app to determine
Timeout            // Integer of seconds to wait before attempting another OTP read (default 10)
ActiveWindowDelay  // Integer in Milliseconds to delay when window is activated (default 300)
KeystrokeDelay     // Integer in Milliseconds to delay the keystrokes when typing (default 10)
PortBinding        // Integer - This is a high range port simply used to prevent multiple instances from running (default 48237)
ShowNotifications  // Boolean True or false setting for showing the pop up notifications (default True)
EnableLogs         // Boolean True or false setting for diagnostic logging of activity (default True)
MaxLogHistory      // Integer for Maximum number of lines to keep in the log, older lines will roll off (default 500)

# Installation

Sample Installation powershell script is provided.  In order for the application to work across all applications (particularly target applications being run under other user contexts such as administrator) it is highly recommended that the compiled source code be digitally signed using a trusted certificate, and then it is necessary to place the signed executable in the "C:\Program Files" directory.

# Usage

Once the application is launched, the icon will appear in the system tray.  Right click to show a menu that allows access to the diagnostic screen.  The diagnostic screen will display the active window, as well as various diagnostic messages useful for testing purposes.  These messages can be exported to a file if necessary.  The menu also has an "about" option and the "exit" option.

# Version

Current version is 0.80
To do:
- Add configuration option for URI - I would like it to be more flexible in URI handling
- More testing on various Windows builds
