// Popular / well-known root domains. Static list — no Tranco fetch, no cron.
// Two jobs:
//   1. Skip young-domain / registrar / favicon heuristics on known-big sites
//      (a legit site younger than 30 days on this list was Safe yesterday too).
//   2. Brand-in-subdomain test skips popular parents so outlook.live.com,
//      mail.google.com etc. don't false-positive.
// Curated by hand from top-sites rankings; add freely.

const POPULAR_ROOTS = new Set([
  // corpus benign entries (keep benchmark + prod aligned)
  "google.com", "youtube.com", "facebook.com", "amazon.com", "microsoft.com",
  "apple.com", "netflix.com", "paypal.com", "github.com", "linkedin.com",
  "twitter.com", "reddit.com", "dropbox.com", "chase.com", "wellsfargo.com",
  "bankofamerica.com", "citibank.com", "hsbc.com", "fedex.com", "ups.com",
  "dhl.com", "usps.com", "coinbase.com", "binance.com", "shopify.com",
  "ebay.com", "icloud.com", "office.com", "ycombinator.com", "vercel.com",
  "stripe.com", "figma.com", "notion.so", "slack.com", "zoom.us",
  "discord.com", "spotify.com", "twitch.tv", "wayfair.com", "target.com",
  "bestbuy.com",
  // big brand property domains commonly seen as parents of legit subdomains
  "live.com", "outlook.com", "hotmail.com", "gmail.com", "msn.com", "bing.com",
  "microsoftonline.com", "office365.com", "azure.com", "azurewebsites.net",
  "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube-nocookie.com",
  "whatsapp.com", "instagram.com", "messenger.com", "meta.com",
  "tiktok.com", "snapchat.com", "pinterest.com", "tumblr.com", "medium.com",
  "substack.com", "x.com", "telegram.org", "signal.org", "wikipedia.org",
  "duckduckgo.com", "mozilla.org", "chrome.com", "android.com",
  "walmart.com", "costco.com", "homedepot.com", "lowes.com", "ikea.com",
  "newegg.com", "etsy.com", "aliexpress.com", "alibaba.com", "chewy.com",
  "airbnb.com", "booking.com", "expedia.com", "uber.com", "lyft.com",
  "americanexpress.com", "visa.com", "mastercard.com", "capitalone.com",
  "discover.com", "fidelity.com", "schwab.com", "vanguard.com", "robinhood.com",
  "venmo.com", "cash.app", "revolut.com", "wise.com", "skrill.com",
  "kraken.com", "bitstamp.net", "gemini.com", "openai.com", "anthropic.com",
  "cloudflare.com", "fastly.net", "akamai.com", "digitalocean.com",
  "herokuapp.com", "netlify.app", "github.io", "gitlab.com", "stackexchange.com",
  "stackoverflow.com", "npmjs.com", "docker.com", "adobe.com", "docusign.com",
  "canva.com", "norton.com", "mcafee.com", "bbc.com", "cnn.com", "reuters.com",
  "nytimes.com", "washingtonpost.com", "theguardian.com", "bloomberg.com",
  "irs.gov", "ssa.gov", "gov.uk", "usa.gov", "usa.gov",
  "zendesk.com", "freshdesk.com", "intercom.io", "att.com", "verizon.com",
  "comcast.net", "t-mobile.com", "sprint.com", "starbucks.com",
  "playstation.com", "xbox.com", "nintendo.com", "steampowered.com",
]);

function isPopularRoot(root) {
  if (!root) return false;
  return POPULAR_ROOTS.has(root.toLowerCase().replace(/^www\./, ""));
}

export { POPULAR_ROOTS, isPopularRoot };
