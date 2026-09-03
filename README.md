# NFC-OTP Bridge

I had a need for a lightweight application that could read a YubiOTP code from a YubiKey over NFC.  Written in Go, this is what I came up with.

This is a Windows system tray application that monitors for a target application window to receive the focus, and then waits for the user to tap a YubiKey on an NFC reader.  The application will capture and parse the OTP, and then "type" it into the target window.  This is designed to work with the default YubiKey programming, which has a URI NDEF programmed from the factory.

# Configuration

The configuration is normally stored in the registry, under HKCU\Software\YubiNFC-OTP.  However, on first run, it will look for the existence of a config.ini file in the application directory.  If present, it will load those values into the registry.  If not present, it will use hard coded default values.

Configuration Values:
---------------------
