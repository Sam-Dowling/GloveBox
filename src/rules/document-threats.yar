rule PDF_JavaScript_Execution
{
    meta:
        description = "PDF contains JavaScript references — can be used for exploitation"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059.007"
        applies_to  = "pdf"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/JavaScript"
        $b = "/JS "
        $c = "/JS("

    condition:
        $pdf at 0 and any of ($a, $b, $c)
}

rule PDF_AutoOpen_Action
{
    meta:
        description = "PDF uses OpenAction or Additional Actions to auto-execute on open"
        severity    = "high"
        category    = "execution"
        mitre       = "T1204.002"
        applies_to  = "pdf"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/OpenAction"
        $b = "/AA"

    condition:
        $pdf at 0 and ($a or $b)
}

rule PDF_Launch_Action
{
    meta:
        description = "PDF uses /Launch to execute external programs"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1204.002"
        applies_to  = "pdf"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/Launch"

    condition:
        $pdf at 0 and $a
}

rule PDF_Embedded_File_Attachment
{
    meta:
        description = "PDF contains embedded file attachments — potential payload delivery"
        severity    = "medium"
        category    = "delivery"
        mitre       = "T1566.001"
        applies_to  = "pdf"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/EmbeddedFile"
        $b = "/Filespec"

    condition:
        $pdf at 0 and ($a or $b)
}

rule PDF_Obfuscated_Stream
{
    meta:
        description = "PDF uses multiple unusual encoding filters — may hide malicious content"
        severity    = "medium"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "pdf"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/ASCIIHexDecode"
        $b = "/ASCII85Decode"
        $c = "/LZWDecode"
        $d = "/RunLengthDecode"

    condition:
        $pdf at 0 and 2 of ($a, $b, $c, $d)
}

rule PDF_SubmitForm_Action
{
    meta:
        description = "PDF uses /SubmitForm — can exfiltrate form data to external URL"
        severity    = "high"
        category    = "exfiltration"
        mitre       = "T1048"
        applies_to  = "pdf"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/SubmitForm"

    condition:
        $pdf at 0 and $a
}

rule PDF_URI_Link
{
    meta:
        description = "PDF contains URI action — may redirect to phishing or malware site"
        severity    = "low"
        category    = "initial-access"
        mitre       = "T1566.002"
        applies_to  = "pdf"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/URI"
        $b = "/S /URI"

    condition:
        $pdf at 0 and ($a or $b)
}

rule PDF_GoToR_Remote_Link
{
    meta:
        description = "PDF uses /GoToR to open a remote PDF — can chain to exploit"
        severity    = "high"
        category    = "initial-access"
        mitre       = "T1566.002"
        applies_to  = "pdf"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/GoToR"
        $b = "/GoToE"

    condition:
        $pdf at 0 and ($a or $b)
}

rule PDF_XFA_Form
{
    meta:
        description = "PDF contains XFA forms — complex attack surface, historically exploited"
        severity    = "high"
        category    = "execution"
        mitre       = "T1203"
        applies_to  = "pdf"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/XFA"
        $b = "xdp:xdp" nocase
        $c = "xfa:data" nocase

    condition:
        $pdf at 0 and any of ($a, $b, $c)
}

rule PDF_Encrypted_Content
{
    meta:
        description = "PDF is encrypted — may bypass content scanning by email gateways"
        severity    = "medium"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "pdf"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/Encrypt"

    condition:
        $pdf at 0 and $a
}

rule PDF_Phishing_QR_Code_Indicators
{
    meta:
        description = "PDF contains image XObjects — may be an image-only PDF used for QR code phishing (quishing)"
        severity    = "medium"
        category    = "initial-access"
        mitre       = "T1566.002"
        applies_to  = "pdf"

    strings:
        $pdf = { 25 50 44 46 }
        $a = "/Image"
        $b = "/XObject"
        $c = "/Subtype /Image"

    condition:
        $pdf at 0 and ($a and $b and $c)
}

rule RTF_Embedded_Object
{
    meta:
        description = "RTF document contains embedded OLE object"
        severity    = "high"
        category    = "execution"
        mitre       = "T1204.002"
        applies_to  = "rtf"

    strings:
        $rtf = "{\\rtf"
        $a = "{\\object"
        $b = "\\objdata"
        $c = "\\objemb"

    condition:
        $rtf at 0 and any of ($a, $b, $c)
}

rule RTF_Equation_Editor_Exploit
{
    meta:
        description = "RTF references Equation Editor CLSID — CVE-2017-11882 / CVE-2018-0802"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1203"
        applies_to  = "rtf"

    strings:
        $rtf = "{\\rtf"
        $clsid = "0002ce02" nocase

    condition:
        $rtf at 0 and $clsid
}

rule RTF_Obfuscated_Header
{
    meta:
        description = "RTF with heavy obfuscation — absurdly long control words or hex escapes"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "rtf"

    strings:
        $rtf = "{\\rtf"
        $junk1 = /\{\\[a-z]{20,}/
        $junk2 = /\\'\w\w\\'\w\w\\'\w\w\\'\w\w/

    condition:
        $rtf at 0 and ($junk1 or $junk2)
}

rule RTF_Large_Hex_Blob
{
    meta:
        description = "RTF with very large hex-encoded data blob — likely embedded payload"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "rtf"

    strings:
        $rtf = "{\\rtf"
        $a = "\\objdata"
        $hex = /[0-9a-fA-F]{500,}/

    condition:
        $rtf at 0 and $a and $hex
}

rule RTF_Package_Object
{
    meta:
        description = "RTF contains packager shell object — drops files to disk"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1204.002"
        applies_to  = "rtf"

    strings:
        $rtf = "{\\rtf"
        $a = "Package" nocase
        $b = "\\object"
        $c = "OLE2Link" nocase

    condition:
        $rtf at 0 and 2 of ($a, $b, $c)
}

rule OneNote_Embedded_Script
{
    meta:
        description = "OneNote file with embedded script or executable file references"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1204.002"
        applies_to  = "onenote"

    strings:
        $magic = { E4 52 5C 7B 8C D8 A7 4D }
        $a = ".bat" wide
        $b = ".cmd" wide
        $c = ".hta" wide
        $d = ".vbs" wide
        $e = ".js" wide
        $f = ".ps1" wide
        $g = ".exe" wide
        $h = ".wsf" wide

    condition:
        $magic and any of ($a, $b, $c, $d, $e, $f, $g, $h)
}

rule OneNote_Any_Embedded_File
{
    meta:
        description = "OneNote file with any embedded file attachment — review for payloads"
        severity    = "high"
        category    = "delivery"
        mitre       = "T1566.001"
        applies_to  = "onenote"

    strings:
        $magic = { E4 52 5C 7B 8C D8 A7 4D }
        $a = { 00 00 00 00 E7 16 E3 BD }

    condition:
        $magic and $a
}

rule SVG_Redirect_Phish
{
    meta:
        description = "SVG image with embedded link or meta redirect — phishing lure disguised as image"
        severity    = "high"
        category    = "initial-access"
        mitre       = "T1566.002"
        applies_to  = "svg"

    strings:
        $svg = "<svg" nocase
        $a = "<a " nocase
        $b = "href=" nocase
        $c = "xlink:href=" nocase
        $d = "http-equiv=\"refresh\"" nocase

    condition:
        $svg and 2 of ($a, $b, $c, $d)
}

rule SVG_Base64_Embedded_Content
{
    meta:
        description = "SVG with large base64 data URI — may smuggle hidden content"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "svg"

    strings:
        $svg = "<svg" nocase
        $a = "data:text/html;base64" nocase
        $b = "data:application" nocase
        $c = "data:image/svg+xml;base64" nocase

    condition:
        $svg and any of ($a, $b, $c)
}

rule HTML_Smuggling
{
    meta:
        description = "HTML file using blob/download smuggling to deliver hidden payload"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1027.006"
        applies_to  = "is_html, svg, eml, msg"

    strings:
        $a = "new Blob" nocase
        $b = "URL.createObjectURL" nocase
        $c = "msSaveOrOpenBlob" nocase
        $d = "download=" nocase
        $e = ".click()"
        $f = "atob("
        $g = "Uint8Array"

    condition:
        3 of them
}

rule HTML_Credential_Phish_Form
{
    meta:
        description = "HTML file with password input and brand impersonation or external form action"
        severity    = "high"
        category    = "credential-access"
        mitre       = "T1056.003"
        applies_to  = "is_html, svg, eml, msg"

    strings:
        $form = "<form" nocase
        $pwd1 = "type=\"password\"" nocase
        $pwd2 = "type='password'" nocase
        $act1 = "action=\"http" nocase
        $act2 = "action='http" nocase
        $brand1 = "Microsoft" nocase
        $brand2 = "Office 365" nocase
        $brand3 = "SharePoint" nocase
        $brand4 = "OneDrive" nocase
        $brand5 = "Adobe" nocase
        $brand6 = "DocuSign" nocase
        $brand7 = "Google" nocase

    condition:
        $form and ($pwd1 or $pwd2) and ($act1 or $act2 or $brand1 or $brand2 or $brand3 or $brand4 or $brand5 or $brand6 or $brand7)
}

rule HTML_Meta_Redirect_Phish
{
    meta:
        description = "HTML file with meta refresh redirect — used in phishing redirectors"
        severity    = "high"
        category    = "initial-access"
        mitre       = "T1566.002"
        applies_to  = "is_html, svg, eml, msg"

    strings:
        $a = "http-equiv=\"refresh\"" nocase
        $b = "http-equiv='refresh'" nocase
        $c = "url=" nocase
        $d = "<meta" nocase

    condition:
        ($a or $b) and $c and $d
}

rule HTML_JavaScript_Redirect
{
    meta:
        description = "HTML with JavaScript redirect — common phishing redirector technique"
        severity    = "high"
        category    = "initial-access"
        mitre       = "T1566.002"
        applies_to  = "is_html, svg, eml, msg"

    strings:
        $a = "window.location" nocase
        $b = "location.href" nocase
        $c = "location.replace" nocase
        $d = "document.location" nocase
        $e = "<script" nocase

    condition:
        $e and any of ($a, $b, $c, $d)
}

rule HTML_Obfuscated_Phish_Page
{
    meta:
        description = "HTML page with heavy obfuscation — typical of advanced phishing kits"
        severity    = "critical"
        category    = "credential-access"
        mitre       = "T1056.003"
        applies_to  = "is_html, svg, eml, msg"

    strings:
        $a = "atob(" nocase
        $b = "String.fromCharCode" nocase
        $c = "unescape(" nocase
        $d = "document.write(" nocase
        $e = "eval(" nocase
        $f = "type=\"password\"" nocase
        $g = "type='password'" nocase

    condition:
        ($f or $g) and 2 of ($a, $b, $c, $d, $e)
}

rule HTML_Invisible_Iframe
{
    meta:
        description = "HTML page with hidden/invisible iframe — clickjacking or silent redirect"
        severity    = "high"
        category    = "initial-access"
        mitre       = "T1566.002"
        applies_to  = "is_html, svg, eml, msg"

    strings:
        $a = "<iframe" nocase
        $b = "display:none" nocase
        $c = "visibility:hidden" nocase
        $d = "width=\"0\"" nocase
        $e = "height=\"0\"" nocase
        $f = "width:0" nocase
        $g = "height:0" nocase

    condition:
        $a and any of ($b, $c, $d, $e, $f, $g)
}

rule HTML_Captcha_Phish_Gate
{
    meta:
        description = "HTML phishing page with fake CAPTCHA gate — delays analysis, builds trust"
        severity    = "high"
        category    = "initial-access"
        mitre       = "T1566.002"
        applies_to  = "is_html, svg, eml, msg"

    strings:
        $a = "captcha" nocase
        $b = "verify" nocase
        $c = "human" nocase
        $d = "type=\"password\"" nocase
        $e = "robot" nocase

    condition:
        3 of them
}

rule HTML_LocalStorage_Exfil
{
    meta:
        description = "HTML phishing page accesses localStorage or sessionStorage — credential caching"
        severity    = "medium"
        category    = "credential-access"
        mitre       = "T1056.003"
        applies_to  = "is_html, svg, eml, msg"

    strings:
        $a = "localStorage" nocase
        $b = "sessionStorage" nocase
        $c = "setItem" nocase
        $d = "getItem" nocase
        $e = "password" nocase

    condition:
        ($a or $b) and ($c or $d) and $e
}

rule HTML_Data_URI_Payload
{
    meta:
        description = "HTML file uses data URI to embed executable or script content"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "is_html, svg, eml, msg"

    strings:
        $a = "data:text/html;base64" nocase
        $b = "data:application/x-javascript" nocase
        $c = "data:application/octet-stream" nocase
        $d = "data:text/javascript" nocase

    condition:
        any of them
}

rule HTML_WebSocket_Exfil
{
    meta:
        description = "HTML page opens WebSocket connection — potential credential exfiltration channel"
        severity    = "medium"
        category    = "exfiltration"
        mitre       = "T1048"
        applies_to  = "is_html, svg, eml, msg"

    strings:
        $a = "new WebSocket" nocase
        $b = "WebSocket(" nocase
        $c = "wss://" nocase
        $d = "password" nocase

    condition:
        ($a or $b or $c) and $d
}

rule IQY_Web_Query_File
{
    meta:
        description = "IQY web query file starting with WEB header — fetches remote data into Excel, abused for C2"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1559.002"
        applies_to  = "iqyslk"

    strings:
        $a = /^WEB\r?\n/
        $b = "http" nocase

    condition:
        $a and $b
}

rule SLK_Symbolic_Link_File
{
    meta:
        description = "SLK (Symbolic Link) spreadsheet file starting with ID;P header — legacy format that bypasses macro blocks"
        severity    = "high"
        category    = "execution"
        mitre       = "T1204.002"
        applies_to  = "iqyslk"

    strings:
        $a = "ID;P" nocase

    condition:
        $a at 0
}

rule CSV_Formula_Injection
{
    meta:
        description = "CSV file with formula injection — payloads execute when opened in Excel"
        severity    = "high"
        category    = "execution"
        mitre       = "T1204.002"

    strings:
        $a = "=CMD(" nocase
        $b = "=EXEC(" nocase
        $c = "=SYSTEM(" nocase
        $d = /^=[A-Z]+\(/ nocase
        $e = "+cmd" nocase
        $f = "-cmd" nocase
        $g = "@SUM(" nocase
        $h = "=HYPERLINK(" nocase

    condition:
        any of ($a, $b, $c, $e, $f) or ($d and ($g or $h))
}

rule PDF_AcroForm_With_JavaScript
{
    meta:
        description = "PDF has AcroForm combined with JavaScript — interactive form exploitation"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059.007"
        applies_to  = "pdf"

    strings:
        $pdf   = { 25 50 44 46 }
        $acro  = "/AcroForm"
        $js1   = "/JavaScript"
        $js2   = "/JS"

    condition:
        $pdf at 0 and $acro and ($js1 or $js2)
}

rule PDF_RichMedia_Content
{
    meta:
        description = "PDF contains RichMedia (Flash/multimedia) — historically exploited attack surface"
        severity    = "high"
        category    = "execution"
        mitre       = "T1203"
        applies_to  = "pdf"

    strings:
        $pdf   = { 25 50 44 46 }
        $a     = "/RichMedia"

    condition:
        $pdf at 0 and $a
}

rule PDF_ObjectStream_With_Action
{
    meta:
        description = "PDF uses object streams with auto-action — can hide malicious objects"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "pdf"

    strings:
        $pdf   = { 25 50 44 46 }
        $obj   = "/ObjStm"
        $a     = "/OpenAction"
        $b     = "/AA"
        $c     = "/JavaScript"

    condition:
        $pdf at 0 and $obj and any of ($a, $b, $c)
}

rule PDF_Eval_Obfuscation
{
    meta:
        description = "PDF contains JavaScript eval or encoding functions — obfuscated exploit code"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1059.007"
        applies_to  = "pdf"

    strings:
        $pdf   = { 25 50 44 46 }
        $js    = "/JavaScript"
        $a     = "eval" nocase
        $b     = "String.fromCharCode" nocase
        $c     = "unescape" nocase
        $d     = "atob" nocase

    condition:
        $pdf at 0 and $js and 2 of ($a, $b, $c, $d)
}

rule HTML_Entity_Obfuscated_Script
{
    meta:
        description = "HTML file uses numeric character entities to hide script content"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "is_html, svg, eml, msg"

    strings:
        $entity_chain = /(&#x?[0-9a-fA-F]{2,4};){10,}/ ascii
        $script_tag = "<script" nocase
        $eval = "eval" nocase

    condition:
        $entity_chain and ($script_tag or $eval)
}

rule MHTML_Smuggling
{
    meta:
        description = "MHTML file with embedded active content — smuggles payloads through MIME wrapping"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027.006"
        applies_to  = "is_html, svg, eml, msg"

    strings:
        $mime    = "MIME-Version:" nocase
        $mhtml1  = "Content-Location:" nocase
        $mhtml2  = "Content-Type: multipart/related" nocase
        $mhtml3  = "Content-Type: message/rfc822" nocase
        $active1 = "<script" nocase
        $active2 = "ActiveXObject" nocase
        $active3 = "WScript.Shell" nocase
        $active4 = "<HTA:APPLICATION" nocase

    condition:
        $mime and any of ($mhtml*) and any of ($active*)
}

rule OneNote_Embedded_PE
{
    meta:
        description = "OneNote file with embedded MZ PE executable — payload delivery via notebook"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1204.002"
        applies_to  = "onenote"

    strings:
        $magic = { E4 52 5C 7B 8C D8 A7 4D }
        $mz    = { 4D 5A 90 00 }
        $pe    = "This program cannot be run in DOS mode"

    condition:
        $magic and ($mz or $pe)
}

rule HTML_Smuggling_Password_Hint
{
    meta:
        description = "HTML smuggling page includes password hint text — common malware delivery pattern"
        severity    = "critical"
        category    = "defense-evasion"
        mitre       = "T1027.006"
        applies_to  = "is_html, svg, eml, msg"

    strings:
        $blob   = "new Blob" nocase
        $b64    = "atob(" nocase
        $dl     = "download=" nocase
        $pw1    = "password" nocase
        $pw2    = "passcode" nocase
        $pw3    = "Password:" nocase
        $zip    = ".zip" nocase

    condition:
        ($blob or $b64) and $dl and any of ($pw*) and $zip
}

rule RTF_ObjUpdate_AutoExec
{
    meta:
        description = "RTF with \\objupdate auto-execution — highest-signal RTF dropper indicator"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1203"
        applies_to  = "rtf"

    strings:
        $rtf       = "{\\rtf"
        $object    = "\\object" nocase
        $objdata   = "\\objdata" nocase
        $objupdate = "\\objupdate" nocase

    condition:
        $rtf at 0 and $object and $objdata and $objupdate
}

rule RTF_ObjClass_Exploit
{
    meta:
        description = "RTF with high-risk OLE object class — maps to known exploit families or dropper techniques"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1203"
        applies_to  = "rtf"

    strings:
        $rtf      = "{\\rtf"
        $objclass = "\\objclass" nocase
        $eq3      = "Equation.3" nocase
        $eq4      = "Equation.DSMT4" nocase
        $ole2link = "OLE2Link" nocase
        $package  = "\\objclass Package" nocase
        $html1    = "htmlfile" nocase
        $html2    = "MSForms.HTMLFile" nocase

    condition:
        $rtf at 0 and $objclass and ($eq3 or $eq4 or $ole2link or $package or $html1 or $html2)
}

rule OOXML_External_Template
{
    meta:
        description = "OOXML document with external relationship target — template injection or remote OLE"
        severity    = "high"
        category    = "initial-access"
        mitre       = "T1221"
        applies_to  = "is_office_ooxml"

    strings:
        $extmode   = "TargetMode=\"External\"" nocase
        $template  = "attachedTemplate" nocase
        $dotm      = ".dotm" nocase
        $http      = "Target=\"http" nocase
        $unc       = "Target=\"\\\\" nocase
        $oleobj    = "oleObject" nocase

    condition:
        $extmode and ($template or $dotm or $http or $unc or $oleobj)
}

rule OOXML_DDE_Field_Code
{
    meta:
        description = "OOXML document with DDE or dangerous field code in w:instrText — code execution without macros"
        severity    = "high"
        category    = "execution"
        mitre       = "T1559.002"
        applies_to  = "is_office_ooxml"

    strings:
        $instr1 = "w:instrText" nocase
        $instr2 = "w:fldSimple" nocase
        $dde1   = "DDEAUTO" nocase
        $dde2   = "DDE " nocase
        $inc1   = "INCLUDETEXT" nocase
        $inc2   = "INCLUDEPICTURE" nocase
        $import = "IMPORT " nocase
        $quote  = "QUOTE " nocase

    condition:
        ($instr1 or $instr2) and ($dde1 or $dde2 or $inc1 or $inc2 or $import or $quote)
}

rule RTF_Nested_Objects
{
    meta:
        description = "RTF with multiple nested OLE objects or nested RTF — parser-confusion evasion technique"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
        applies_to  = "rtf"

    strings:
        $rtf    = "{\\rtf"
        $obj    = "{\\object" nocase
        $nested = "{\\rtf1" nocase

    condition:
        $rtf at 0 and (#obj > 2 or #nested > 1)
}
