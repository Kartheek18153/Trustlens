// Self-check for isCheckableHost. Run with: node tests/check_checkable.mjs
import { isCheckableHost } from "../background/domain.js";

function expect(label, got, want) {
  const ok = got === want;
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + got + " want=" + want);
  if (!ok) process.exitCode = 1;
}

expect("paypal.com",          isCheckableHost("paypal.com"),         true);
expect("www.paypal.com",      isCheckableHost("www.paypal.com"),     true);
expect("chrome://extensions", isCheckableHost("chrome://extensions"),false);
expect("newtab",              isCheckableHost("newtab"),             false);
expect("localhost",           isCheckableHost("localhost"),          false);
expect("192.168.1.1",         isCheckableHost("192.168.1.1"),        false);
expect("single",              isCheckableHost("single"),             false);
expect("xn--pypal-4ve.com",   isCheckableHost("xn--pypal-4ve.com"),  true);
