// Curated top brand list for typosquat / homoglyph / favicon-pHash detection.
// ~200 entries spanning the categories most targeted by phishing.
// Add your own — the popup settings page exposes this list.

export const BRANDS = [
  // Tech giants
  "google", "youtube", "gmail", "googlecom", "chrome", "android", "googledrive",
  "facebook", "meta", "instagram", "whatsapp", "messenger", "oculus",
  "microsoft", "outlook", "office365", "office", "onedrive", "sharepoint", "teams",
  "skype", "xbox", "bing", "msn", "azure", "github", "gitlab",
  "apple", "icloud", "itunes", "appstore", "macos", "me", "mac",
  "amazon", "amazoncom", "prime", "aws", "alexa", "ring", "twitch",
  "netflix", "spotify", "disneyplus", "hulu", "hbomax", "paramountplus",
  // Social / comms
  "twitter", "x", "tiktok", "snapchat", "pinterest", "tumblr", "reddit",
  "linkedin", "discord", "telegram", "signal", "viber", "line", "wechat",
  "medium", "substack", "threads", "mastodon", "bluesky",
  // Payments / finance
  "paypal", "stripe", "square", "venmo", "zelle", "cashapp", "revolut",
  "wise", "payoneer", "skrill", "adyen", "klarna", "afterpay",
  "coinbase", "binance", "kraken", "bitstamp", "gemini", "crypto",
  "metamask", "trustwallet", "ledger", "trezor", "phantom",
  "wellsfargo", "chase", "bankofamerica", "citibank", "hsbc", "barclays",
  "santander", "natwest", "lloyds", "deutschebank", "ing", "bnpparibas",
  "americanexpress", "amex", "visa", "mastercard", "discover", "capitalone",
  "fidelity", "schwab", "vanguard", "robinhood", "etoro", "interactivebrokers",
  // Shipping / logistics
  "fedex", "ups", "dhl", "usps", "royal mail", "parcelforce", "dpd",
  "hermes", "yodel", "tnt", "aramex", "sf-express", "ems", "japanpost",
  // Retail / e-commerce
  "shopify", "ebay", "etsy", "aliexpress", "alibaba", "lazada", "shopee",
  "wayfair", "target", "walmart", "costco", "homedepot", "lowes",
  "ikea", "bestbuy", "newegg", "asos", "zara", "hm", "nike", "adidas",
  // Travel
  "airbnb", "booking", "expedia", "hotels", "kayak", "trivago", "agoda",
  "united", "delta", "americanairlines", "southwest", "jetblue", "ryanair",
  "easyjet", "lufthansa", "british-airways", "klm", "airfrance", "emirates",
  "uber", "lyft", "grab", "ola", "bolt", "via", "didi",
  // Productivity
  "dropbox", "box", "notion", "evernote", "onenote", "todoist", "trello",
  "asana", "monday", "clickup", "basecamp", "airtable", "slack",
  "zoom", "webex", "gotomeeting", "whereby", "around", "lark", "feishu",
  // Dev / infra
  "github", "gitlab", "bitbucket", "stackoverflow", "docker", "kubernetes",
  "npm", "pypi", "maven", "terraform", "ansible", "jenkins", "circleci",
  "vercel", "netlify", "cloudflare", "fastly", "akamai", "digitalocean",
  "heroku", "fly", "render", "supabase", "firebase", "openai", "anthropic",
  // Crypto / web3
  "opensea", "rarible", "etherscan", "polygonscan", "uniswap", "aave",
  "compound", "makerdao", "curve", "sushiswap", "pancakeswap", "lido",
  // Media / news
  "nytimes", "wsj", "washingtonpost", "theguardian", "bbc", "cnn",
  "reuters", "apnews", "bloomberg", "forbes", "techcrunch", "theverge",
  "wired", "engadget", "cnet", "zdnet", "arstechnica", "vice",
  // Education / govt
  "irs", "govuk", "uscis", "ssa", "medicare", "edgov", "studentaid",
  "harvard", "mit", "stanford", "coursera", "udemy", "edx", "khanacademy",
  "duolingo", "quizlet",
  // Misc frequently impersonated
  "norton", "mcafee", "kaspersky", "avast", "bitdefender", "malwarebytes",
  "geek-squad", "mintsquad",
  "docusign", "adobe", "acrobat", "photoshop", "figma", "canva", "grammarly",
  "1password", "lastpass", "bitwarden", "dashlane", "keepass",
  "protonmail", "protonvpn", "tutanota", "fastmail",
];

// Common TLDs frequently used to look legit. Checked during homoglyph scan.
export const LEGIT_TLDS = new Set([
  "com", "net", "org", "io", "co", "ai", "app", "dev", "me",
  "uk", "de", "fr", "es", "it", "nl", "se", "no", "fi", "dk",
  "jp", "kr", "cn", "tw", "hk", "sg", "in", "au", "nz", "ca", "mx", "br",
  "edu", "gov", "mil", "int",
]);

// Free email providers — used by the display-name vs address test.
export const FREE_EMAIL_DOMAINS = new Set([
  "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
  "aol.com", "icloud.com", "me.com", "mac.com", "protonmail.com", "proton.me",
  "tutanota.com", "fastmail.com", "zoho.com", "gmx.com", "mail.com",
  "yandex.com", "yandex.ru", "mail.ru", "qq.com", "163.com", "126.com",
  "naver.com", "daum.net", "rocketmail.com", "yahoo.co.uk", "yahoo.co.in",
]);
