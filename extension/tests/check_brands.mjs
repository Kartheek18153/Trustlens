// Self-check that the brand list is at least 200 and has the expected size.
import { BRANDS } from "../background/brands.js";

let failed = false;
console.log("brand list size =", BRANDS.length);
if (BRANDS.length < 200) { console.log("FAIL brand list under 200"); process.exitCode = 1; }
else console.log("PASS brand list >= 200");

const must = ["google", "paypal", "amazon", "microsoft", "apple", "github", "coinbase"];
for (const b of must) {
  if (!BRANDS.includes(b)) { console.log("FAIL missing brand: " + b); failed = true; process.exitCode = 1; }
}
if (!failed) console.log("PASS required brands present");
