// ─── Windows Threats ───
// 126 rules

rule HTA_File_With_Script
{
    meta:
        description = "HTA file with script block and execution capability"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1218.005"

    strings:
        $hta = "<HTA:APPLICATION" nocase
        $script = "<script" nocase
        $vbs = "VBScript" nocase
        $js = "JScript" nocase
        $ps = "powershell" nocase
        $shell = "WScript.Shell" nocase
        $exec = "Run(" nocase

    condition:
        $hta and ($script or $vbs or $js) and ($ps or $shell or $exec)
}

rule HTA_Download_Execute
{
    meta:
        description = "HTA downloads and executes a remote payload"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1218.005"

    strings:
        $hta = "<HTA:APPLICATION" nocase
        $dl1 = "MSXML2.XMLHTTP" nocase
        $dl2 = "Microsoft.XMLHTTP" nocase
        $dl3 = "WinHttp" nocase
        $dl4 = "URLDownloadToFile" nocase
        $dl5 = "Net.WebClient" nocase
        $save = "SaveToFile" nocase
        $stream = "ADODB.Stream" nocase

    condition:
        $hta and ($dl1 or $dl2 or $dl3 or $dl4 or $dl5 or ($save and $stream))
}

rule HTA_Any_Presence
{
    meta:
        description = "File contains HTA application tag — always suspicious as email attachment"
        severity    = "medium"
        category    = "execution"
        mitre       = "T1218.005"

    strings:
        $a = "<HTA:APPLICATION" nocase

    condition:
        $a
}

rule HTA_MSHTA_Inline_Script
{
    meta:
        description = "HTA invoked with mshta inline vbscript or javascript — fileless delivery"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1218.005"

    strings:
        $a = "mshta" nocase
        $b = "vbscript:Execute" nocase
        $c = "javascript:" nocase
        $d = "vbscript:Close" nocase

    condition:
        $a and any of ($b, $c, $d)
}

rule URL_Shortcut_Suspicious
{
    meta:
        description = "Windows .url shortcut with SMB reference or remote icon (credential theft)"
        severity    = "high"
        category    = "credential-access"
        mitre       = "T1187"

    strings:
        $header = "[InternetShortcut]"
        $url = "URL="
        $icon = "IconFile="
        $smb1 = "URL=\\\\\\\\" nocase
        $smb2 = "URL=file://" nocase

    condition:
        $header and $url and ($smb1 or $smb2 or $icon)
}

rule URL_Shortcut_UNC_Icon
{
    meta:
        description = "URL shortcut with UNC path icon reference — NTLM hash theft via SMB"
        severity    = "critical"
        category    = "credential-access"
        mitre       = "T1187"

    strings:
        $header = "[InternetShortcut]"
        $icon = /IconFile=\\\\[^\r\n]+/

    condition:
        $header and $icon
}

rule URL_Shortcut_Any_Presence
{
    meta:
        description = "Any .url internet shortcut file — uncommon as legitimate email attachment"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $a = "[InternetShortcut]"
        $b = "URL="

    condition:
        $a and $b
}

rule URL_Shortcut_To_Script_Handler
{
    meta:
        description = "URL shortcut pointing to script protocol handler (javascript/vbscript/mshta)"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1204.002"

    strings:
        $header = "[InternetShortcut]"
        $a = "URL=javascript:" nocase
        $b = "URL=vbscript:" nocase
        $c = "URL=mshta" nocase
        $d = "URL=file:" nocase

    condition:
        $header and any of ($a, $b, $c, $d)
}

rule LNK_Suspicious_CommandLine
{
    meta:
        description = "LNK shortcut with references to suspicious LOLBins (PowerShell, cmd, mshta, etc.)"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1204.002"

    strings:
        $lnk = { 4C 00 00 00 }
        $a = "cmd" nocase wide
        $b = "powershell" nocase wide
        $c = "mshta" nocase wide
        $d = "wscript" nocase wide
        $e = "cscript" nocase wide
        $f = "rundll32" nocase wide
        $g = "regsvr32" nocase wide
        $h = "certutil" nocase wide
        $i = "bitsadmin" nocase wide
        $j = "msiexec" nocase wide

    condition:
        $lnk and any of ($a, $b, $c, $d, $e, $f, $g, $h, $i, $j)
}

rule LNK_Double_Extension
{
    meta:
        description = "LNK file containing a double-extension string — file masquerade technique"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1036.007"

    strings:
        $lnk = { 4C 00 00 00 }
        $a = ".pdf.lnk" nocase wide
        $b = ".doc.lnk" nocase wide
        $c = ".xlsx.lnk" nocase wide
        $d = ".jpg.lnk" nocase wide
        $e = ".png.lnk" nocase wide
        $f = ".txt.lnk" nocase wide

    condition:
        $lnk and any of ($a, $b, $c, $d, $e, $f)
}

rule LNK_Extended_LOLBins
{
    meta:
        description = "LNK shortcut references less common LOLBins — forfiles, pcalua, explorer abuse"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1218"

    strings:
        $lnk = { 4C 00 00 00 }
        $a = "forfiles" nocase wide
        $b = "pcalua" nocase wide
        $c = "explorer.exe" nocase wide
        $d = "control.exe" nocase wide
        $e = "msconfig" nocase wide
        $f = "fodhelper" nocase wide
        $g = "SyncAppvPublishingServer" nocase wide
        $h = "InstallUtil" nocase wide
        $i = "MSBuild" nocase wide
        $j = "xwizard" nocase wide

    condition:
        $lnk and any of ($a, $b, $c, $d, $e, $f, $g, $h, $i, $j)
}

rule LNK_Script_Target
{
    meta:
        description = "LNK shortcut targets a script file directly (.js, .vbs, .hta, .bat, .ps1)"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1204.002"

    strings:
        $lnk = { 4C 00 00 00 }
        $a = ".js" nocase wide
        $b = ".jse" nocase wide
        $c = ".vbs" nocase wide
        $d = ".vbe" nocase wide
        $e = ".hta" nocase wide
        $f = ".bat" nocase wide
        $g = ".cmd" nocase wide
        $h = ".ps1" nocase wide
        $i = ".wsf" nocase wide

    condition:
        $lnk and any of ($a, $b, $c, $d, $e, $f, $g, $h, $i)
}

rule LNK_Environment_Variable_Abuse
{
    meta:
        description = "LNK shortcut uses environment variable paths — evasion of static path analysis"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"

    strings:
        $lnk = { 4C 00 00 00 }
        $a = "%APPDATA%" nocase wide
        $b = "%TEMP%" nocase wide
        $c = "%USERPROFILE%" nocase wide
        $d = "%PUBLIC%" nocase wide
        $e = "%COMSPEC%" nocase wide
        $f = "%SYSTEMROOT%" nocase wide

    condition:
        $lnk and any of ($a, $b, $c, $d, $e, $f)
}

rule WSF_MultiEngine_Script
{
    meta:
        description = "Windows Script File (.wsf) with embedded script — bypasses script policy"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059"

    strings:
        $a = "<job" nocase
        $b = "<script" nocase
        $c = "language=" nocase
        $d = "WScript" nocase

    condition:
        $a and $b and ($c or $d)
}

rule VHD_Disk_Image
{
    meta:
        description = "VHD/VHDX virtual disk image — MotW bypass, mounts as drive on double-click"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1553.005"

    strings:
        $a = "conectix"
        $b = "vhdxfile"

    condition:
        any of them
}

rule MSI_Installer_Suspicious
{
    meta:
        description = "MSI Windows Installer — uncommon as legitimate email attachment"
        severity    = "high"
        category    = "execution"
        mitre       = "T1218.007"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $a = "SummaryInformation" wide
        $b = "InstallExecuteSequence" wide
        $c = "CustomAction" wide

    condition:
        $ole and any of ($a, $b, $c)
}

rule MSIX_APPX_Installer
{
    meta:
        description = "MSIX/APPX package — abused for sideloading malware via ms-appinstaller"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1218"

    strings:
        $pk = { 50 4B 03 04 }
        $a = "AppxManifest.xml" nocase
        $b = "AppxBlockMap.xml" nocase
        $c = "AppxSignature" nocase

    condition:
        $pk and any of ($a, $b, $c)
}

rule CMSTP_INF_Bypass
{
    meta:
        description = "INF file designed for CMSTP.exe bypass — UAC evasion via connection manager"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1218.003"

    strings:
        $a = "[version]" nocase
        $b = "CMSTP" nocase
        $c = "RegisterOCXSection" nocase
        $d = "UnRegisterOCXSection" nocase
        $e = "RunPreSetupCommandsSection" nocase

    condition:
        $a and ($b or $c or $d or $e)
}

rule Info_Contains_MachO_Binary
{
    meta:
        description = "File contains a Mach-O binary header (macOS/iOS executable)"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $macho32    = { CE FA ED FE }
        $macho64    = { CF FA ED FE }
        $macho_fat  = { CA FE BA BE }

    condition:
        any of them
}

rule Info_Contains_Java_JAR
{
    meta:
        description = "File contains a Java JAR archive (ZIP with META-INF/MANIFEST.MF)"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $pk       = { 50 4B 03 04 }
        $manifest = "META-INF/MANIFEST.MF"

    condition:
        $pk and $manifest
}

rule Info_Contains_Java_Class
{
    meta:
        description = "File contains a compiled Java .class file (magic bytes CAFEBABE)"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $magic = { CA FE BA BE 00 }

    condition:
        $magic
}

rule Info_Contains_DotNet_Assembly
{
    meta:
        description = "File contains .NET CLR assembly indicators"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $mz       = { 4D 5A }
        $mscoree  = "mscoree.dll" nocase
        $clr      = "_CorExeMain" nocase
        $clr2     = "_CorDllMain" nocase
        $metadata = "#Strings" wide
        $metadata2 = "#GUID" wide

    condition:
        $mz and ($mscoree or $clr or $clr2 or 2 of ($metadata, $metadata2))
}

rule Info_Contains_WebAssembly
{
    meta:
        description = "File contains WebAssembly (WASM) binary module"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $magic = { 00 61 73 6D }

    condition:
        $magic
}

rule Info_Contains_DLL_Export
{
    meta:
        description = "File contains DLL export indicators — may be a disguised dynamic library"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $mz      = { 4D 5A }
        $export1 = "DllRegisterServer" nocase
        $export2 = "DllUnregisterServer" nocase
        $export3 = "DllGetClassObject" nocase
        $export4 = "DllCanUnloadNow" nocase
        $export5 = "ServiceMain" nocase

    condition:
        $mz and any of ($export1, $export2, $export3, $export4, $export5)
}

rule Info_Email_EML_Format
{
    meta:
        description = "File is a raw email message (.eml format with standard headers)"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $from    = "From: " nocase
        $to      = "To: " nocase
        $subject = "Subject: " nocase
        $mime    = "MIME-Version:" nocase
        $recv    = "Received:" nocase

    condition:
        3 of them
}

rule Info_Email_Reply_To_Mismatch_Indicator
{
    meta:
        description = "Email contains both From and Reply-To headers — analyst should verify they match"
        severity    = "info"
        category    = "phishing"
        mitre       = "T1566"

    strings:
        $from    = "From:" nocase
        $replyto = "Reply-To:" nocase

    condition:
        $from and $replyto
}

rule Info_Email_SPF_Fail
{
    meta:
        description = "Email headers indicate SPF authentication failure"
        severity    = "info"
        category    = "phishing"
        mitre       = "T1566"

    strings:
        $a = "spf=fail" nocase
        $b = "spf=softfail" nocase
        $c = "spf=temperror" nocase
        $d = "spf=permerror" nocase

    condition:
        any of them
}

rule Info_Email_DKIM_Fail
{
    meta:
        description = "Email headers indicate DKIM signature verification failure"
        severity    = "info"
        category    = "phishing"
        mitre       = "T1566"

    strings:
        $a = "dkim=fail" nocase
        $b = "dkim=temperror" nocase
        $c = "dkim=permerror" nocase

    condition:
        any of them
}

rule Info_Email_DMARC_Fail
{
    meta:
        description = "Email headers indicate DMARC policy failure"
        severity    = "info"
        category    = "phishing"
        mitre       = "T1566"

    strings:
        $a = "dmarc=fail" nocase
        $b = "dmarc=none" nocase

    condition:
        any of them
}

rule Info_Email_X_Originating_IP
{
    meta:
        description = "Email contains X-Originating-IP header — reveals sender's source IP"
        severity    = "info"
        category    = "discovery"
        mitre       = ""

    strings:
        $a = "X-Originating-IP:" nocase

    condition:
        $a
}

rule Info_Email_Multiple_Received_Hops
{
    meta:
        description = "Email has multiple Received headers — may indicate forwarding or relay chain"
        severity    = "info"
        category    = "discovery"
        mitre       = ""

    strings:
        $recv = "Received:" nocase

    condition:
        #recv > 5
}

rule Info_Email_Bulk_Precedence
{
    meta:
        description = "Email marked as bulk, list, or junk precedence — mass mailing indicator"
        severity    = "info"
        category    = "phishing"
        mitre       = ""

    strings:
        $a = "Precedence: bulk" nocase
        $b = "Precedence: junk" nocase
        $c = "Precedence: list" nocase
        $d = "X-Mailer:" nocase

    condition:
        any of ($a, $b, $c)
}

rule Info_Email_Content_Transfer_Encoding
{
    meta:
        description = "Email uses base64 or quoted-printable content transfer encoding"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $a = "Content-Transfer-Encoding: base64" nocase
        $b = "Content-Transfer-Encoding: quoted-printable" nocase

    condition:
        any of them
}

rule Info_Email_Multipart_Mixed
{
    meta:
        description = "Email is multipart/mixed — contains attachments alongside body text"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $a = "Content-Type: multipart/mixed" nocase

    condition:
        $a
}

rule Info_PNG_Appended_Data
{
    meta:
        description = "PNG file with data appended after IEND chunk — possible steganography or payload"
        severity    = "info"
        category    = "defense-evasion"
        mitre       = "T1027.001"

    strings:
        $png_header = { 89 50 4E 47 0D 0A 1A 0A }
        $iend       = { 49 45 4E 44 AE 42 60 82 }

    condition:
        $png_header and $iend and @iend[1] + 8 < filesize
}

rule Info_JPEG_Appended_Data
{
    meta:
        description = "JPEG file with data after the EOI marker — possible hidden payload"
        severity    = "info"
        category    = "defense-evasion"
        mitre       = "T1027.001"

    strings:
        $soi = { FF D8 FF }
        $eoi = { FF D9 }

    condition:
        $soi at 0 and @eoi[#eoi] + 2 < filesize
}

rule Info_Image_Only_HTML_Email
{
    meta:
        description = "HTML content is image-only with no meaningful text — scanner evasion technique"
        severity    = "info"
        category    = "phishing"
        mitre       = "T1566.002"

    strings:
        $html  = "<html" nocase
        $img1  = "<img" nocase
        $img2  = "background-image" nocase
        $no_p  = "<p" nocase
        $no_span = "<span" nocase
        $no_div_text = "<div" nocase

    condition:
        $html and ($img1 or $img2) and not $no_p and not $no_span
}

rule Info_SVG_Image_Present
{
    meta:
        description = "File contains SVG image markup — review for embedded scripts"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $svg = "<svg" nocase
        $xmlns = "xmlns" nocase

    condition:
        $svg and $xmlns
}

rule Info_WMI_Event_Subscription
{
    meta:
        description = "File references WMI event subscription classes — fileless persistence mechanism"
        severity    = "info"
        category    = "persistence"
        mitre       = "T1546.003"

    strings:
        $a = "__EventFilter" nocase
        $b = "__EventConsumer" nocase
        $c = "CommandLineEventConsumer" nocase
        $d = "ActiveScriptEventConsumer" nocase
        $e = "__FilterToConsumerBinding" nocase

    condition:
        any of them
}

rule Info_Service_Installation
{
    meta:
        description = "File references Windows service creation or modification"
        severity    = "info"
        category    = "persistence"
        mitre       = "T1543.003"

    strings:
        $a = "sc create" nocase
        $b = "sc config" nocase
        $c = "New-Service" nocase
        $d = "InstallService" nocase
        $e = "ServiceName" nocase
        $f = "binPath=" nocase

    condition:
        2 of them
}

rule Info_BITSAdmin_Reference
{
    meta:
        description = "File references BITSAdmin — can be abused for stealthy file transfers"
        severity    = "info"
        category    = "defense-evasion"
        mitre       = "T1197"

    strings:
        $a = "bitsadmin" nocase
        $b = "/transfer" nocase
        $c = "Start-BitsTransfer" nocase

    condition:
        any of them
}

rule Info_Alternate_Data_Stream
{
    meta:
        description = "File references NTFS Alternate Data Streams — payload hiding technique"
        severity    = "info"
        category    = "defense-evasion"
        mitre       = "T1564.004"

    strings:
        $a = /[a-zA-Z]:\\[^\s:]+:[^\s:]+/ nocase
        $b = "Zone.Identifier" nocase
        $c = ":$DATA" nocase

    condition:
        any of them
}

rule Info_DLL_Sideload_Indicators
{
    meta:
        description = "File references known DLL sideloading targets"
        severity    = "info"
        category    = "defense-evasion"
        mitre       = "T1574.002"

    strings:
        $a = "version.dll" nocase
        $b = "winmm.dll" nocase
        $c = "dbghelp.dll" nocase
        $d = "wer.dll" nocase
        $e = "CRYPTSP.dll" nocase
        $f = "profapi.dll" nocase

    condition:
        2 of them
}

rule Info_Android_APK
{
    meta:
        description = "File is an Android APK package (ZIP with AndroidManifest.xml)"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $pk       = { 50 4B 03 04 }
        $manifest = "AndroidManifest.xml"
        $dex      = "classes.dex"

    condition:
        $pk and ($manifest or $dex)
}

rule Info_iOS_MobileConfig
{
    meta:
        description = "File is an Apple .mobileconfig profile — can install MDM, VPN, or certs silently"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $plist = "<!DOCTYPE plist" nocase
        $a     = "PayloadType" nocase
        $b     = "PayloadIdentifier" nocase
        $c     = "Configuration" nocase
        $d     = "PayloadContent" nocase

    condition:
        $plist and 2 of ($a, $b, $c, $d)
}

rule Info_ICS_Calendar_Invite
{
    meta:
        description = "File is an iCalendar (.ics) invite — check for phishing URLs in event body"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $begin = "BEGIN:VCALENDAR" nocase
        $event = "BEGIN:VEVENT" nocase
        $url   = "URL:" nocase
        $desc  = "DESCRIPTION:" nocase

    condition:
        $begin and $event
}

rule Info_ICS_Calendar_With_URL
{
    meta:
        description = "Calendar invite (.ics) contains URL — common vector for calendar phishing"
        severity    = "info"
        category    = "phishing"
        mitre       = "T1566.002"

    strings:
        $begin = "BEGIN:VCALENDAR" nocase
        $event = "BEGIN:VEVENT" nocase
        $url1  = "URL:http" nocase
        $url2  = "DESCRIPTION:" nocase
        $url3  = "http" nocase

    condition:
        $begin and $event and ($url1 or ($url2 and $url3))
}

rule Info_Apple_Disk_Image_DMG
{
    meta:
        description = "File is an Apple Disk Image (DMG) — can contain macOS malware"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $a = { 78 01 73 0D 62 62 60 }
        $b = "koly" 
        $c = "dmg" nocase

    condition:
        $a or ($b and $c)
}

rule Info_Shortcut_WEBLOC
{
    meta:
        description = "File is a macOS .webloc bookmark — may redirect to phishing URL"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $plist = "<!DOCTYPE plist" nocase
        $url   = "<key>URL</key>" nocase

    condition:
        $plist and $url
}

rule Info_Linux_Desktop_Entry
{
    meta:
        description = "File is a Linux .desktop application entry — can execute arbitrary commands"
        severity    = "info"
        category    = "execution"
        mitre       = "T1204.002"

    strings:
        $header = "[Desktop Entry]" nocase
        $exec   = "Exec=" nocase
        $type   = "Type=Application" nocase

    condition:
        $header and $exec
}

rule Info_Cloudflare_Workers_URL
{
    meta:
        description = "File references Cloudflare Workers URL — abused for phishing proxies"
        severity    = "info"
        category    = "phishing"
        mitre       = "T1583.001"

    strings:
        $a = ".workers.dev" nocase
        $b = "pages.dev" nocase

    condition:
        any of them
}

rule Info_Azure_Hosting_URL
{
    meta:
        description = "File references Azure hosting domains — sometimes abused for phishing infra"
        severity    = "info"
        category    = "phishing"
        mitre       = "T1583.001"

    strings:
        $a = ".azurewebsites.net" nocase
        $b = ".blob.core.windows.net" nocase
        $c = ".azureedge.net" nocase
        $d = ".azure-api.net" nocase
        $e = ".onmicrosoft.com" nocase

    condition:
        any of them
}

rule Info_AWS_Hosting_URL
{
    meta:
        description = "File references AWS hosting domains — sometimes abused for phishing infra"
        severity    = "info"
        category    = "phishing"
        mitre       = "T1583.001"

    strings:
        $a = ".amazonaws.com" nocase
        $b = ".cloudfront.net" nocase
        $c = ".awsapps.com" nocase
        $d = "s3.amazonaws.com" nocase

    condition:
        any of them
}

rule Info_Google_Cloud_Hosting_URL
{
    meta:
        description = "File references Google Cloud hosting domains"
        severity    = "info"
        category    = "phishing"
        mitre       = "T1583.001"

    strings:
        $a = ".appspot.com" nocase
        $b = ".cloudfunctions.net" nocase
        $c = ".run.app" nocase
        $d = ".web.app" nocase
        $e = ".firebaseapp.com" nocase

    condition:
        any of them
}

rule Info_Firebase_Dynamic_Link
{
    meta:
        description = "File contains Firebase dynamic link — used to create redirect chains"
        severity    = "info"
        category    = "phishing"
        mitre       = "T1583.001"

    strings:
        $a = ".page.link" nocase
        $b = "firebasedynamic" nocase

    condition:
        any of them
}

rule Info_Vercel_Netlify_Hosting
{
    meta:
        description = "File references Vercel or Netlify hosting — abused for disposable phishing sites"
        severity    = "info"
        category    = "phishing"
        mitre       = "T1583.001"

    strings:
        $a = ".vercel.app" nocase
        $b = ".netlify.app" nocase
        $c = ".netlify.com" nocase

    condition:
        any of them
}

rule Info_Heroku_Render_Hosting
{
    meta:
        description = "File references Heroku or Render hosting domains"
        severity    = "info"
        category    = "phishing"
        mitre       = "T1583.001"

    strings:
        $a = ".herokuapp.com" nocase
        $b = ".onrender.com" nocase

    condition:
        any of them
}

rule Info_Tracking_Pixel
{
    meta:
        description = "File contains a 1x1 tracking pixel image — used for open-tracking or canary"
        severity    = "info"
        category    = "collection"
        mitre       = "T1114"

    strings:
        $a = "width=\"1\" height=\"1\"" nocase
        $b = "width='1' height='1'" nocase
        $c = "width:1px;height:1px" nocase
        $d = "width=1 height=1" nocase
        $e = "width=\"1\"" nocase

    condition:
        any of ($a, $b, $c, $d) and ($e)
}

rule Info_External_Image_Load
{
    meta:
        description = "Document or HTML loads an external image — may phone home on open"
        severity    = "info"
        category    = "collection"
        mitre       = "T1114"

    strings:
        $img_http1 = "<img" nocase
        $img_http2 = "src=\"http" nocase
        $img_http3 = "src='http" nocase
        $bg_img    = "background=\"http" nocase
        $css_bg    = "url(http" nocase

    condition:
        ($img_http1 and ($img_http2 or $img_http3)) or $bg_img or $css_bg
}

rule Info_Unique_Token_In_URL
{
    meta:
        description = "File contains URL with long unique token — per-recipient tracking link"
        severity    = "info"
        category    = "collection"
        mitre       = "T1114"

    strings:
        $a = /https?:\/\/[^\s]{10,}[?&][a-zA-Z]+=[-a-zA-Z0-9_]{20,}/

    condition:
        $a
}

rule Info_Web_Beacon_Keywords
{
    meta:
        description = "File contains web beacon or tracking-related keywords"
        severity    = "info"
        category    = "collection"
        mitre       = "T1114"

    strings:
        $a = "web beacon" nocase
        $b = "tracking pixel" nocase
        $c = "open tracking" nocase
        $d = "read receipt" nocase
        $e = "canarytoken" nocase
        $f = "canarytokens.com" nocase

    condition:
        any of them
}

rule Info_UTF7_Encoded_Content
{
    meta:
        description = "File contains UTF-7 encoded sequences — used to bypass XSS and content filters"
        severity    = "info"
        category    = "defense-evasion"
        mitre       = "T1027"

    strings:
        $a = "+ADw-script" nocase
        $b = "+ADw-img" nocase
        $c = "+ADw-iframe" nocase
        $d = "+ADw-svg" nocase
        $e = "+ACI-" nocase

    condition:
        any of them
}

rule Info_MIME_Encoded_Words
{
    meta:
        description = "File contains MIME encoded-word syntax — may hide subject or filename"
        severity    = "info"
        category    = "defense-evasion"
        mitre       = "T1027"

    strings:
        $b64  = /=\?[A-Za-z0-9\-]+\?B\?[A-Za-z0-9+\/=]+\?=/
        $qp   = /=\?[A-Za-z0-9\-]+\?Q\?[^\?]+\?=/

    condition:
        any of them
}

rule Info_Quoted_Printable_Obfuscation
{
    meta:
        description = "File contains heavy quoted-printable encoding — may obfuscate phishing text"
        severity    = "info"
        category    = "defense-evasion"
        mitre       = "T1027"

    strings:
        $qp = /=[0-9A-Fa-f]{2}/

    condition:
        #qp > 50
}

rule Info_HTML_Entity_Obfuscation
{
    meta:
        description = "File uses heavy HTML entity encoding — evasion of text-based content scanning"
        severity    = "info"
        category    = "defense-evasion"
        mitre       = "T1027"

    strings:
        $dec = /&#[0-9]{2,4};/
        $hex = /&#x[0-9a-fA-F]{2,4};/

    condition:
        #dec > 20 or #hex > 20
}

rule Info_CSS_Content_Injection
{
    meta:
        description = "HTML uses CSS content property to render text — hides text from parsers"
        severity    = "info"
        category    = "defense-evasion"
        mitre       = "T1027"

    strings:
        $a = "content:" nocase
        $b = "::before" nocase
        $c = "::after" nocase
        $d = "attr(" nocase

    condition:
        $a and ($b or $c or $d)
}

rule Info_Zero_Width_Characters
{
    meta:
        description = "File contains zero-width Unicode characters — text obfuscation or fingerprinting"
        severity    = "info"
        category    = "defense-evasion"
        mitre       = "T1027"

    strings:
        $zwsp  = { E2 80 8B }
        $zwnj  = { E2 80 8C }
        $zwj   = { E2 80 8D }
        $bom   = { EF BB BF }
        $wj    = { E2 81 A0 }

    condition:
        2 of them
}

rule Info_Punycode_Domain
{
    meta:
        description = "File contains a Punycode-encoded domain (xn--) — possible homograph attack"
        severity    = "info"
        category    = "initial-access"
        mitre       = "T1583.001"

    strings:
        $a = "xn--" nocase

    condition:
        $a
}

rule Info_Data_URI_Scheme
{
    meta:
        description = "File contains data: URI scheme — may embed content inline to avoid fetching"
        severity    = "info"
        category    = "defense-evasion"
        mitre       = "T1027"

    strings:
        $a = "data:text/html" nocase
        $b = "data:application/" nocase
        $c = "data:image/svg+xml" nocase
        $d = "data:text/javascript" nocase

    condition:
        any of them
}

rule Info_Cobalt_Strike_Indicators
{
    meta:
        description = "File contains strings associated with Cobalt Strike beacons"
        severity    = "info"
        category    = "command-and-control"
        mitre       = "T1071.001"

    strings:
        $a = "beacon.dll" nocase
        $b = "beacon.exe" nocase
        $c = "%COMSPEC%" nocase
        $d = "IEX (New-Object Net.Webclient).DownloadString" nocase
        $e = "/submit.php?" nocase
        $f = "pipe\\msse-" nocase

    condition:
        2 of them
}

rule Info_Metasploit_Indicators
{
    meta:
        description = "File contains strings commonly seen in Metasploit payloads"
        severity    = "info"
        category    = "execution"
        mitre       = "T1059"

    strings:
        $a = "meterpreter" nocase
        $b = "metasploit" nocase
        $c = "reverse_tcp" nocase
        $d = "reverse_http" nocase
        $e = "shell_bind_tcp" nocase
        $f = "windows/exec" nocase

    condition:
        any of them
}

rule Info_Macro_Builder_Artifacts
{
    meta:
        description = "File contains artifacts from known macro payload builders"
        severity    = "info"
        category    = "execution"
        mitre       = "T1059.005"

    strings:
        $a = "MacroPack" nocase
        $b = "EvilClippy" nocase
        $c = "Unicorn" nocase
        $d = "LuckyStrike" nocase
        $e = "macro_reverse" nocase

    condition:
        any of them
}

rule Info_Mimikatz_Reference
{
    meta:
        description = "File contains references to Mimikatz credential harvesting tool"
        severity    = "info"
        category    = "credential-access"
        mitre       = "T1003.001"

    strings:
        $a = "mimikatz" nocase
        $b = "sekurlsa" nocase
        $c = "kerberos::list" nocase
        $d = "lsadump" nocase
        $e = "gentilkiwi" nocase

    condition:
        any of them
}

rule Info_DNS_Over_HTTPS_Reference
{
    meta:
        description = "File references DNS-over-HTTPS endpoints — can be used for covert C2"
        severity    = "info"
        category    = "command-and-control"
        mitre       = "T1071.001"

    strings:
        $a = "dns.google/resolve" nocase
        $b = "cloudflare-dns.com/dns-query" nocase
        $c = "dns.quad9.net" nocase
        $d = "doh.opendns.com" nocase
        $e = "application/dns-json" nocase

    condition:
        any of them
}

rule Info_DNS_TXT_Lookup
{
    meta:
        description = "File performs DNS TXT record lookups — can smuggle data or instructions"
        severity    = "info"
        category    = "command-and-control"
        mitre       = "T1071.004"

    strings:
        $a = "nslookup" nocase
        $b = "-type=TXT" nocase
        $c = "Resolve-DnsName" nocase
        $d = "QueryType TXT" nocase
        $e = "dig " nocase

    condition:
        ($a and $b) or ($c and $d) or $e
}

rule Info_Exfil_HTTP_POST
{
    meta:
        description = "File constructs HTTP POST requests with data — possible exfiltration"
        severity    = "info"
        category    = "exfiltration"
        mitre       = "T1048"

    strings:
        $a = "XMLHttpRequest" nocase
        $b = ".open(\"POST\"" nocase
        $c = ".open('POST'" nocase
        $d = "fetch(" nocase
        $e = "method: 'POST'" nocase
        $f = "method:\"POST\"" nocase
        $g = "Content-Type" nocase

    condition:
        ($a and ($b or $c) and $g) or ($d and ($e or $f))
}

rule Info_Socket_Connection
{
    meta:
        description = "File creates raw socket or TCP connection — possible reverse shell or C2"
        severity    = "info"
        category    = "command-and-control"
        mitre       = "T1095"

    strings:
        $a = "TCPClient" nocase
        $b = "Net.Sockets" nocase
        $c = "socket.connect" nocase
        $d = "new Socket" nocase
        $e = "SOCK_STREAM" nocase
        $f = "WSAStartup" nocase

    condition:
        any of them
}

rule Info_Reverse_Shell_Patterns
{
    meta:
        description = "File contains common reverse shell connection patterns"
        severity    = "info"
        category    = "execution"
        mitre       = "T1059"

    strings:
        $a = "/dev/tcp/" nocase
        $b = "bash -i" nocase
        $c = "nc -e" nocase
        $d = "ncat -e" nocase
        $e = "python -c 'import socket" nocase
        $f = "0>&1" nocase
        $g = "exec 5<>/dev/tcp" nocase

    condition:
        any of them
}

rule Info_Browser_Credential_Paths
{
    meta:
        description = "File references browser credential or cookie store paths"
        severity    = "info"
        category    = "credential-access"
        mitre       = "T1555.003"

    strings:
        $a = "Login Data" nocase
        $b = "Cookies" nocase
        $c = "\\Google\\Chrome\\User Data" nocase
        $d = "\\Mozilla\\Firefox\\Profiles" nocase
        $e = "\\Microsoft\\Edge\\User Data" nocase
        $f = "logins.json" nocase
        $g = "signons.sqlite" nocase

    condition:
        2 of them
}

rule Info_Keylogger_Indicators
{
    meta:
        description = "File contains keylogger-related API calls or patterns"
        severity    = "info"
        category    = "collection"
        mitre       = "T1056.001"

    strings:
        $a = "GetAsyncKeyState" nocase
        $b = "SetWindowsHookEx" nocase
        $c = "GetKeyState" nocase
        $d = "WH_KEYBOARD" nocase
        $e = "keylog" nocase

    condition:
        2 of them
}

rule Info_Screenshot_Capture
{
    meta:
        description = "File contains screen capture API references"
        severity    = "info"
        category    = "collection"
        mitre       = "T1113"

    strings:
        $a = "GetDesktopWindow" nocase
        $b = "BitBlt" nocase
        $c = "CopyFromScreen" nocase
        $d = "Screenshot" nocase
        $e = "PrintWindow" nocase

    condition:
        2 of them
}

rule Info_Webcam_Microphone_Access
{
    meta:
        description = "File references webcam or microphone access APIs"
        severity    = "info"
        category    = "collection"
        mitre       = "T1125"

    strings:
        $a = "getUserMedia" nocase
        $b = "MediaDevices" nocase
        $c = "avicap32" nocase
        $d = "capCreateCaptureWindow" nocase
        $e = "waveInOpen" nocase
        $f = "navigator.mediaDevices" nocase

    condition:
        2 of them
}

rule Info_Sensitive_File_Extensions
{
    meta:
        description = "File references sensitive data file extensions (wallets, databases, keys)"
        severity    = "info"
        category    = "collection"
        mitre       = "T1005"

    strings:
        $a = ".kdbx" nocase
        $b = ".kdb" nocase
        $c = ".wallet" nocase
        $d = ".pfx" nocase
        $e = ".p12" nocase
        $f = ".pem" nocase
        $g = ".rdp" nocase
        $h = ".ovpn" nocase
        $i = ".ppk" nocase

    condition:
        any of them
}

rule Info_Outlook_Credential_Reference
{
    meta:
        description = "File references Outlook profile credentials or PST/OST archives"
        severity    = "info"
        category    = "credential-access"
        mitre       = "T1114.001"

    strings:
        $a = ".pst" nocase fullword
        $b = ".ost" nocase fullword
        $c = "Outlook\\Profiles" nocase
        $d = "IMAP Password" nocase
        $e = "POP3 Password" nocase
        $f = "SMTP Password" nocase

    condition:
        2 of them
}

rule Info_VM_Detection_Strings
{
    meta:
        description = "File checks for virtual machine or sandbox environment indicators"
        severity    = "info"
        category    = "defense-evasion"
        mitre       = "T1497.001"

    strings:
        $a = "VMware" nocase
        $b = "VirtualBox" nocase
        $c = "QEMU" nocase
        $d = "Hyper-V" nocase
        $e = "Xen" nocase
        $f = "vboxservice" nocase
        $g = "vmtoolsd" nocase
        $h = "SbieDll" nocase
        $i = "sandboxie" nocase
        $j = "cuckoomon" nocase

    condition:
        2 of them
}

rule Info_Debugger_Detection
{
    meta:
        description = "File checks for debugger presence — anti-analysis technique"
        severity    = "info"
        category    = "defense-evasion"
        mitre       = "T1497.001"

    strings:
        $a = "IsDebuggerPresent" nocase
        $b = "CheckRemoteDebuggerPresent" nocase
        $c = "NtQueryInformationProcess" nocase
        $d = "OutputDebugString" nocase
        $e = "OllyDbg" nocase
        $f = "x64dbg" nocase

    condition:
        2 of them
}

rule Info_Timing_Based_Evasion
{
    meta:
        description = "File uses timing checks — common sandbox evasion to wait out analysis"
        severity    = "info"
        category    = "defense-evasion"
        mitre       = "T1497.003"

    strings:
        $a = "GetTickCount" nocase
        $b = "QueryPerformanceCounter" nocase
        $c = "NtDelayExecution" nocase
        $d = "TimeSpan" nocase
        $e = "Thread.Sleep" nocase
        $f = "time.sleep" nocase

    condition:
        2 of them
}

rule Info_Process_Enumeration
{
    meta:
        description = "File enumerates running processes — recon or AV-detection technique"
        severity    = "info"
        category    = "discovery"
        mitre       = "T1057"

    strings:
        $a = "CreateToolhelp32Snapshot" nocase
        $b = "Process32First" nocase
        $c = "Process32Next" nocase
        $d = "EnumProcesses" nocase
        $e = "Get-Process" nocase
        $f = "tasklist" nocase

    condition:
        2 of them
}

rule Info_UAC_Bypass_Indicators
{
    meta:
        description = "File contains references to UAC bypass techniques"
        severity    = "info"
        category    = "privilege-escalation"
        mitre       = "T1548.002"

    strings:
        $a = "fodhelper" nocase
        $b = "eventvwr" nocase
        $c = "sdclt" nocase
        $d = "slui" nocase
        $e = "CompMgmtLauncher" nocase
        $f = "ms-settings" nocase

    condition:
        2 of them
}

rule BITSAdmin_Download
{
    meta:
        description = "BITSAdmin used for file download — LOLBin download technique"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1197"

    strings:
        $a     = "bitsadmin" nocase
        $b     = "/transfer" nocase
        $c     = "/download" nocase
        $d     = "http" nocase

    condition:
        $a and ($b or $c) and $d
}

rule Regsvr32_Remote_SCT
{
    meta:
        description = "Regsvr32 loads remote scriptlet — Squiblydoo AppLocker bypass"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1218.010"

    strings:
        $a     = "regsvr32" nocase
        $b     = "/s" nocase
        $c     = "/n" nocase
        $d     = "/u" nocase
        $e     = "/i:http" nocase
        $f     = "scrobj.dll" nocase

    condition:
        $a and ($e or $f)
}

rule MSBuild_Inline_Task
{
    meta:
        description = "MSBuild XML with inline task — bypasses application whitelisting"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1127.001"

    strings:
        $a     = "<Project" nocase
        $b     = "<UsingTask" nocase
        $c     = "TaskFactory" nocase
        $d     = "CodeTaskFactory" nocase
        $e     = "DllImport" nocase
        $f     = "ProcessStartInfo" nocase

    condition:
        $a and $b and ($c or $d) and ($e or $f)
}

rule CMSTP_CommandLine_Execution
{
    meta:
        description = "CMSTP.exe INF-based execution — UAC bypass and AppLocker evasion"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1218.003"

    strings:
        $a     = "cmstp" nocase
        $b     = "/ni" nocase
        $c     = "/s" nocase
        $d     = ".inf" nocase
        $e     = "RunPreSetupCommandsSection" nocase

    condition:
        ($a and ($b or $c) and $d) or $e
}

rule Msiexec_Remote_Install
{
    meta:
        description = "Msiexec loads remote MSI package — payload delivery via Windows Installer"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1218.007"

    strings:
        $a     = "msiexec" nocase
        $b     = "/i" nocase
        $c     = "/q" nocase
        $d     = "http" nocase

    condition:
        $a and $b and $d
}

rule Rundll32_Script_Proxy
{
    meta:
        description = "Rundll32 used to proxy-execute JavaScript or DLL exports"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1218.011"

    strings:
        $a     = "rundll32" nocase
        $b     = "javascript:" nocase
        $c     = "mshtml" nocase
        $d     = "advpack.dll" nocase
        $e     = "ieadvpack.dll" nocase
        $f     = "syssetup.dll" nocase
        $g     = "setupapi.dll" nocase

    condition:
        $a and any of ($b, $c, $d, $e, $f, $g)
}

rule REG_Persistence_Run_Key
{
    meta:
        description = "Registry file modifies Run/RunOnce autostart keys (persistence)"
        severity    = "critical"
        category    = "persistence"
        mitre       = "T1547.001"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $run1 = "CurrentVersion\\Run]" nocase
        $run2 = "CurrentVersion\\RunOnce]" nocase
        $run3 = "CurrentVersion\\RunOnceEx]" nocase
        $run4 = "CurrentVersion\\RunServices]" nocase

    condition:
        ($header1 or $header2) and any of ($run*)
}

rule REG_Persistence_Winlogon
{
    meta:
        description = "Registry file modifies Winlogon keys (persistence/credential theft)"
        severity    = "critical"
        category    = "persistence"
        mitre       = "T1547.004"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $wl1 = "CurrentVersion\\Winlogon" nocase
        $wl2 = "\"Userinit\"" nocase
        $wl3 = "\"Shell\"" nocase

    condition:
        ($header1 or $header2) and $wl1 and any of ($wl2, $wl3)
}

rule REG_Security_Disable
{
    meta:
        description = "Registry file disables Windows security features"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1562.001"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $dis1 = "DisableAntiSpyware" nocase
        $dis2 = "DisableRealtimeMonitoring" nocase
        $dis3 = "DisableBehaviorMonitoring" nocase
        $dis4 = "DisableOnAccessProtection" nocase
        $dis5 = "DisableScanOnRealtimeEnable" nocase
        $dis6 = "DisableAntiVirus" nocase
        $dis7 = "Windows Defender" nocase

    condition:
        ($header1 or $header2) and any of ($dis*)
}

rule REG_IFEO_Debugger
{
    meta:
        description = "Registry file sets Image File Execution Options debugger (process hijack)"
        severity    = "critical"
        category    = "persistence"
        mitre       = "T1546.012"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $ifeo = "Image File Execution Options" nocase
        $dbg = "\"Debugger\"" nocase

    condition:
        ($header1 or $header2) and $ifeo and $dbg
}

rule REG_Service_Creation
{
    meta:
        description = "Registry file creates or modifies Windows services"
        severity    = "high"
        category    = "persistence"
        mitre       = "T1543.003"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $svc1 = "\\Services\\" nocase
        $svc2 = "\"ImagePath\"" nocase
        $svc3 = "\"Start\"=dword:" nocase

    condition:
        ($header1 or $header2) and $svc1 and any of ($svc2, $svc3)
}

rule REG_UAC_Disable
{
    meta:
        description = "Registry file disables User Account Control"
        severity    = "critical"
        category    = "privilege-escalation"
        mitre       = "T1548.002"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $uac1 = "EnableLUA" nocase
        $uac2 = "ConsentPromptBehaviorAdmin" nocase
        $uac3 = "PromptOnSecureDesktop" nocase

    condition:
        ($header1 or $header2) and any of ($uac*)
}

rule REG_COM_Hijack
{
    meta:
        description = "Registry file modifies COM class registration (COM hijacking)"
        severity    = "high"
        category    = "persistence"
        mitre       = "T1546.015"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $com1 = "\\Classes\\CLSID\\" nocase
        $com2 = "InprocServer32" nocase
        $com3 = "\\Classes\\*\\shell" nocase

    condition:
        ($header1 or $header2) and any of ($com*)
}

rule REG_Suspicious_Values
{
    meta:
        description = "Registry file contains suspicious executable references in values"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $v1 = "powershell" nocase
        $v2 = "cmd.exe" nocase
        $v3 = "mshta" nocase
        $v4 = "regsvr32" nocase
        $v5 = "rundll32" nocase
        $v6 = "certutil" nocase
        $v7 = "bitsadmin" nocase
        $v8 = "wscript" nocase
        $v9 = "cscript" nocase
        $v10 = "-EncodedCommand" nocase
        $v11 = "FromBase64String" nocase
        $v12 = "DownloadString" nocase
        $v13 = "DownloadFile" nocase

    condition:
        ($header1 or $header2) and 2 of ($v*)
}

rule REG_File_Association_Hijack
{
    meta:
        description = "Registry file modifies file associations or shell handlers"
        severity    = "high"
        category    = "persistence"
        mitre       = "T1546.001"

    strings:
        $header1 = "Windows Registry Editor" nocase
        $header2 = "REGEDIT4"
        $fa1 = "\\Classes\\.exe\\" nocase
        $fa2 = "\\Classes\\exefile\\" nocase
        $fa3 = "\\Classes\\htmlfile\\" nocase
        $fa4 = "\\Classes\\http\\" nocase
        $fa5 = "\\shell\\open\\command" nocase

    condition:
        ($header1 or $header2) and any of ($fa*)
}

rule REG_Any_Presence
{
    meta:
        description = "Windows Registry import file detected"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $header1 = "Windows Registry Editor Version 5.00"
        $header2 = "REGEDIT4"

    condition:
        any of them
}

// ════════════════════════════════════════════════════════════════════════
// INF — Windows Setup Information File rules
// ════════════════════════════════════════════════════════════════════════

rule INF_Command_Execution
{
    meta:
        description = "INF file with RunPreSetupCommands or RunPostSetupCommands (command execution)"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1218.003"

    strings:
        $sec1 = "[RunPreSetupCommands]" nocase
        $sec2 = "[RunPostSetupCommands]" nocase
        $cmd1 = "RunPreSetupCommands" nocase
        $cmd2 = "RunPostSetupCommands" nocase

    condition:
        any of them
}

rule INF_CMSTP_Bypass
{
    meta:
        description = "INF file references CMSTP (UAC bypass technique T1218.003)"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1218.003"

    strings:
        $cmstp1 = "cmstp" nocase
        $cmstp2 = "CMSTP.EXE" nocase
        $inf1 = "[DefaultInstall" nocase

    condition:
        any of ($cmstp*) and $inf1
}

rule INF_LOLBin_Reference
{
    meta:
        description = "INF file references LOLBins (Living-off-the-Land binaries)"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1218"

    strings:
        $inf = "[DefaultInstall" nocase
        $lol1 = "rundll32" nocase
        $lol2 = "regsvr32" nocase
        $lol3 = "mshta" nocase
        $lol4 = "certutil" nocase
        $lol5 = "bitsadmin" nocase
        $lol6 = "scrobj.dll" nocase
        $lol7 = "msiexec" nocase

    condition:
        $inf and any of ($lol*)
}

rule INF_Script_Execution
{
    meta:
        description = "INF file references script interpreters"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059"

    strings:
        $inf = "[DefaultInstall" nocase
        $sc1 = "powershell" nocase
        $sc2 = "cmd.exe" nocase
        $sc3 = "wscript" nocase
        $sc4 = "cscript" nocase
        $sc5 = "cmd /c" nocase
        $sc6 = "cmd /k" nocase

    condition:
        $inf and any of ($sc*)
}

rule INF_Registry_Modification
{
    meta:
        description = "INF file with AddReg/DelReg directives (registry modification)"
        severity    = "medium"
        category    = "persistence"
        mitre       = "T1112"

    strings:
        $addreg = "AddReg" nocase
        $delreg = "DelReg" nocase
        $hklm = "HKLM" nocase
        $hkcu = "HKCU" nocase

    condition:
        any of ($addreg, $delreg) and any of ($hklm, $hkcu)
}

rule INF_DLL_Registration
{
    meta:
        description = "INF file registers DLLs or OCX components"
        severity    = "high"
        category    = "execution"
        mitre       = "T1218.010"

    strings:
        $reg1 = "RegisterDlls" nocase
        $reg2 = "UnRegisterDlls" nocase
        $reg3 = "RegisterOCXs" nocase
        $reg4 = "UnRegisterOCXs" nocase

    condition:
        any of them
}

rule INF_URL_Reference
{
    meta:
        description = "INF file contains URL references"
        severity    = "medium"
        category    = "command-and-control"
        mitre       = "T1105"

    strings:
        $url1 = "http://" nocase
        $url2 = "https://" nocase
        $inf = "[Version]" nocase

    condition:
        $inf and any of ($url*)
}

rule INF_Any_Presence
{
    meta:
        description = "Windows Setup Information file detected"
        severity    = "info"
        category    = "file-type"
        mitre       = ""

    strings:
        $ver = "[Version]" nocase
        $sig1 = "Signature=" nocase
        $sig2 = "$Chicago$"
        $sig3 = "$Windows NT$"

    condition:
        $ver and any of ($sig*)
}

// ════════════════════════════════════════════════════════════════════════
// SCT — Windows Script Component (COM Scriptlet) rules
// ════════════════════════════════════════════════════════════════════════

rule SCT_Squiblydoo
{
    meta:
        description = "SCT scriptlet with regsvr32 references (Squiblydoo attack T1218.010)"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1218.010"

    strings:
        $sct1 = "<scriptlet" nocase
        $sct2 = "<registration" nocase
        $reg1 = "regsvr32" nocase
        $reg2 = "scrobj.dll" nocase

    condition:
        any of ($sct*) and any of ($reg*)
}

rule SCT_Script_Execution
{
    meta:
        description = "SCT scriptlet with embedded script code"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059"

    strings:
        $sct = "<scriptlet" nocase
        $sc1 = "<script" nocase
        $lang1 = "JScript" nocase
        $lang2 = "VBScript" nocase

    condition:
        $sct and $sc1 and any of ($lang*)
}

rule SCT_COM_Object_Creation
{
    meta:
        description = "SCT scriptlet creates COM objects (code execution)"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059"

    strings:
        $sct = "<scriptlet" nocase
        $com1 = "CreateObject" nocase
        $com2 = "GetObject" nocase
        $com3 = "WScript.Shell" nocase
        $com4 = "Shell.Application" nocase
        $com5 = "Scripting.FileSystemObject" nocase

    condition:
        $sct and any of ($com*)
}

rule SCT_Network_Access
{
    meta:
        description = "SCT scriptlet with network access capabilities"
        severity    = "high"
        category    = "command-and-control"
        mitre       = "T1105"

    strings:
        $sct = "<scriptlet" nocase
        $net1 = "XMLHTTP" nocase
        $net2 = "MSXML2" nocase
        $net3 = "WinHttp" nocase
        $net4 = "ADODB.Stream" nocase
        $net5 = "DownloadFile" nocase
        $net6 = "DownloadString" nocase

    condition:
        $sct and any of ($net*)
}

rule SCT_Shell_Command
{
    meta:
        description = "SCT scriptlet executes shell commands"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1059"

    strings:
        $sct = "<scriptlet" nocase
        $cmd1 = "powershell" nocase
        $cmd2 = "cmd.exe" nocase
        $cmd3 = "cmd /c" nocase
        $cmd4 = ".Run" nocase
        $cmd5 = ".Exec" nocase
        $cmd6 = "mshta" nocase

    condition:
        $sct and 2 of ($cmd*)
}

rule SCT_Any_Presence
{
    meta:
        description = "Windows Script Component (SCT/WSC scriptlet) detected"
        severity    = "medium"
        category    = "file-type"
        mitre       = ""

    strings:
        $sct1 = "<scriptlet" nocase
        $sct2 = "<registration" nocase
        $sct3 = "classid=" nocase

    condition:
        $sct1 and any of ($sct2, $sct3)
}

// ════════════════════════════════════════════════════════════════════════
// MSI — Windows Installer Package rules
// ════════════════════════════════════════════════════════════════════════

rule MSI_Embedded_PE
{
    meta:
        description = "MSI installer contains embedded PE executable"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1218.007"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $mz1 = { 4D 5A 90 00 }
        $mz2 = { 4D 5A 50 45 }
        $pe  = "This program cannot be run in DOS mode"

    condition:
        $ole at 0 and (any of ($mz*) or $pe)
}

rule MSI_Embedded_Script
{
    meta:
        description = "MSI installer contains embedded script content"
        severity    = "high"
        category    = "execution"
        mitre       = "T1218.007"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $sc1 = "WScript.Shell" nocase
        $sc2 = "Scripting.FileSystemObject" nocase
        $sc3 = "CreateObject" nocase
        $sc4 = "powershell" nocase
        $sc5 = "cmd.exe /c" nocase
        $sc6 = "Shell.Application" nocase

    condition:
        $ole at 0 and 2 of ($sc*)
}

rule MSI_Suspicious_CustomAction
{
    meta:
        description = "MSI installer references CustomAction execution patterns"
        severity    = "high"
        category    = "execution"
        mitre       = "T1218.007"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $ca = "CustomAction" nocase
        $cmd1 = "powershell" nocase
        $cmd2 = "cmd.exe" nocase
        $cmd3 = "mshta" nocase
        $cmd4 = "wscript" nocase
        $cmd5 = "cscript" nocase
        $cmd6 = "certutil" nocase
        $cmd7 = "bitsadmin" nocase
        $cmd8 = "rundll32" nocase

    condition:
        $ole at 0 and $ca and any of ($cmd*)
}

rule MSI_Network_Indicators
{
    meta:
        description = "MSI installer contains network URL references"
        severity    = "medium"
        category    = "command-and-control"
        mitre       = "T1105"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $url1 = "http://" nocase
        $url2 = "https://" nocase
        $url3 = "ftp://" nocase

    condition:
        $ole at 0 and any of ($url*)
}

rule MSI_Encoded_Content
{
    meta:
        description = "MSI installer contains Base64 or encoded command indicators"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "FromBase64String" nocase
        $enc4 = "Convert]::FromBase64" nocase

    condition:
        $ole at 0 and any of ($enc*)
}

rule MSI_Service_Install
{
    meta:
        description = "MSI installer creates Windows services"
        severity    = "medium"
        category    = "persistence"
        mitre       = "T1543.003"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $svc1 = "ServiceInstall" nocase
        $svc2 = "ServiceControl" nocase

    condition:
        $ole at 0 and any of ($svc*)
}

/* ══════════════════════════════════════════════════════════════════════════
   Command Obfuscation Detection Rules
   ══════════════════════════════════════════════════════════════════════════ */

rule URL_Encoded_Command
{
    meta:
        description = "File contains URL-encoded sequences that decode to suspicious commands"
        severity    = "medium"
        category    = "defense-evasion"
        mitre       = "T1027"

    strings:
        $ps = "%70%6f%77%65%72%73%68%65%6c%6c" nocase
        $cmd = "%63%6d%64%2e%65%78%65" nocase
        $wscript = "%77%73%63%72%69%70%74" nocase
        $http = "%68%74%74%70%3a%2f%2f" nocase
        $https = "%68%74%74%70%73%3a%2f%2f" nocase

    condition:
        any of them
}

// ════════════════════════════════════════════════════════════════════════
// ClickOnce Application Reference
// ════════════════════════════════════════════════════════════════════════

rule ClickOnce_AppRef_MS
{
    meta:
        description = "ClickOnce .appref-ms application reference — can install .NET malware on click"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1204.002"

    strings:
        $appref  = ".application#" nocase
        $culture = "Culture=" nocase
        $token   = "PublicKeyToken=" nocase
        $proc    = "processorArchitecture=" nocase
        $http    = "http" nocase

    condition:
        $appref and any of ($culture, $token, $proc) and $http
}

// ════════════════════════════════════════════════════════════════════════
// Scheduled Task XML
// ════════════════════════════════════════════════════════════════════════

rule Scheduled_Task_XML
{
    meta:
        description = "File contains Windows Scheduled Task XML definition — persistence or execution"
        severity    = "high"
        category    = "persistence"
        mitre       = "T1053.005"

    strings:
        $task   = "<Task " nocase
        $xmlns  = "schemas.microsoft.com/windows" nocase
        $exec   = "<Exec>" nocase
        $cmd    = "<Command>" nocase
        $args   = "<Arguments>" nocase
        $trigger1 = "<LogonTrigger>" nocase
        $trigger2 = "<BootTrigger>" nocase
        $trigger3 = "<TimeTrigger>" nocase
        $trigger4 = "<CalendarTrigger>" nocase

    condition:
        $task and $xmlns and $exec and $cmd and any of ($trigger*)
}

// ════════════════════════════════════════════════════════════════════════
// ISO Disk Image
// ════════════════════════════════════════════════════════════════════════

rule ISO_Disk_Image
{
    meta:
        description = "ISO disk image file — bypasses MotW on Windows, mounts on double-click"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1553.005"

    strings:
        $cd001 = "CD001" ascii
        $el_torito = "EL TORITO" nocase
        $iso = "ISO 9660" nocase

    condition:
        $cd001 or ($el_torito and $iso)
}

