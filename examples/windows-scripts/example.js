// Loupe example — benign .js file
// Demonstrates a few patterns the script scanner flags at low severity
// so you can see how Loupe surfaces findings. This file does NOTHING harmful.

'use strict';

function greet(name) {
  return 'Hello, ' + name;
}

// The following is commented out and exists only to exercise the YARA/script
// scanners. It is NOT executed.
// var sh = new ActiveXObject('WScript.Shell');
// sh.Run('calc.exe');

console.log(greet('world'));
