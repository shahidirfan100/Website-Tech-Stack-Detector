# Website Tech Stack Scanner

> **Identify technologies used on any website** - Fast, efficient tech stack detection with smart fallback mechanisms. Detect frameworks, libraries, CMS, WAFs, APIs, and more.

[![Apify Actor](https://img.shields.io/badge/Apify-Actor-blue)](https://apify.com)
[![Tech Detection](https://img.shields.io/badge/Detection-TechStack-green)](https://apify.com)
[![Fast & Reliable](https://img.shields.io/badge/Speed-Optimized-orange)](https://apify.com)

## 📋 What This Actor Does

Website Tech Stack Scanner efficiently identifies technologies powering any website. Using a smart multi-tier approach, it prioritizes fast, resource-light methods before resorting to browser rendering. Perfect for:

- **Technology Research** - Discover what technologies competitors use
- **Lead Generation** - Find websites built with specific tech stacks
- **Security Analysis** - Identify WAFs and security layers
- **Development Planning** - Research technology choices for projects
- **Market Intelligence** - Track technology adoption trends

### ✨ Key Features

- **Smart Detection Strategy** - HTTP headers → Static HTML → API probes → Browser rendering
- **Comprehensive Analysis** - Frameworks, CMS, libraries, WAFs, analytics, hosting
- **WAF Detection** - Identifies Cloudflare, Akamai, PerimeterX, Imperva, and more
- **API Endpoint Probing** - Discovers backend APIs and frameworks
- **Fast & Efficient** - Lightweight analysis before browser usage
- **Structured Data** - Extracts JSON-LD and Open Graph metadata

## 🚀 Quick Start

### Basic Usage - Single Website

```json
{
  "urls": ["https://example.com"],
  "maxConcurrency": 5
}
```

### Advanced Usage - Multiple Sites with Deep Analysis

```json
{
  "urls": [
    "https://example.com",
    "https://another-site.com"
  ],
  "maxConcurrency": 3,
  "usePlaywrightFallback": true,
  "probeApiEndpoints": true
}
```

### Batch Analysis

```json
{
  "urls": [
    "https://site1.com",
    "https://site2.com",
    "https://site3.com"
  ],
  "maxConcurrency": 5,
  "probeApiEndpoints": true
}
```

## 📊 Input Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `urls` | array | Website URLs to analyze (required) | `[]` |
| `maxConcurrency` | integer | Concurrent requests (1-20) | `5` |
| `usePlaywrightFallback` | boolean | Use browser for client-side apps | `true` |
| `probeApiEndpoints` | boolean | Check common API endpoints | `true` |
| `timeout` | integer | Request timeout in seconds | `30` |
| `proxyConfiguration` | object | Proxy settings | `{"useApifyProxy": true}` |

## 📈 Output Data Structure

Each website analysis includes:

```json
{
  "url": "https://example.com",
  "status": "success",
  "technologies": {
    "frontend": ["React 18.2.0", "Next.js 13.4.0"],
    "backend": ["Node.js", "Express"],
    "cms": ["WordPress 6.3"],
    "analytics": ["Google Analytics", "Hotjar"],
    "hosting": ["Vercel"],
    "cdn": ["Cloudflare"],
    "libraries": ["jQuery 3.6.0", "Bootstrap 5.2"]
  },
  "waf": {
    "detected": true,
    "provider": "Cloudflare",
    "confidence": "high"
  },
  "apis": {
    "graphql": true,
    "rest": true,
    "endpoints": ["/api/v1", "/graphql"]
  },
  "metadata": {
    "title": "Example Website",
    "description": "Example description",
    "structuredData": {...}
  },
  "server": {
    "software": "nginx/1.21.0",
    "headers": {...}
  },
  "detectionMethod": "static",
  "scannedAt": "2024-12-11T10:30:00.000Z"
}
```

### Output Fields

- **`url`** - Analyzed website URL
- **`status`** - Analysis status (success/failed/partial)
- **`technologies`** - Categorized tech stack
- **`waf`** - Web Application Firewall details
- **`apis`** - Discovered API endpoints
- **`metadata`** - Page metadata and structured data
- **`server`** - Server and hosting information
- **`detectionMethod`** - How technologies were detected (static/browser/mixed)
- **`scannedAt`** - Analysis timestamp

## 🎯 Detection Methods

### 1. HTTP Headers Analysis (Fastest)
- Server headers
- X-Powered-By headers
- Set-Cookie patterns
- Security headers

### 2. Static HTML Parsing
- Meta tags
- Script src attributes
- Link tags (stylesheets, fonts)
- HTML comments and patterns

### 3. API Endpoint Probing
- Common API paths: `/api`, `/graphql`, `/_next/static`
- CMS endpoints: `/wp-json`, `/admin`
- Framework-specific paths: `/_nuxt/`, `/__nextjs_`

### 4. Browser Rendering (Fallback)
- Window object inspection
- Dynamic content loading
- Client-side frameworks (React, Vue, Angular)
- JavaScript libraries

## 🔍 Detected Technologies

### Frameworks & Libraries
- **Frontend**: React, Vue, Angular, Svelte, Next.js, Nuxt.js, Gatsby
- **Backend**: Express, Django, Laravel, Ruby on Rails, ASP.NET
- **UI**: Bootstrap, Tailwind CSS, Material-UI, Ant Design

### CMS & Platforms
- WordPress, Drupal, Joomla, Shopify, Magento, Wix, Squarespace

### WAFs & Security
- Cloudflare, Akamai, PerimeterX, Imperva, Kasada, Datadome

### Analytics & Marketing
- Google Analytics, Tag Manager, Facebook Pixel, Hotjar, Mixpanel

### Hosting & CDN
- Vercel, Netlify, AWS, GCP, Azure, Cloudflare, Fastly

## ⚡ Performance Tips

### Recommended Settings

| Use Case | URLs | Concurrency | Playwright | API Probe | Est. Time |
|----------|------|-------------|------------|-----------|-----------|
| Quick Check | 1-5 | 5 | `false` | `false` | ~5-10s |
| Standard Analysis | 5-20 | 3-5 | `true` | `true` | ~30-60s |
| Batch Processing | 20-100 | 5-10 | `true` | `true` | ~2-5m |

### Cost Optimization

1. **Disable Playwright** for static sites (faster, cheaper)
2. **Reduce concurrency** to avoid rate limits
3. **Use proxies** for large batches
4. **Filter URLs** to analyze only relevant pages

## 🔧 Configuration Examples

### Security Audit

```json
{
  "urls": ["https://target-site.com"],
  "usePlaywrightFallback": false,
  "probeApiEndpoints": true,
  "maxConcurrency": 1
}
```

### Competitor Analysis

```json
{
  "urls": [
    "https://competitor1.com",
    "https://competitor2.com",
    "https://competitor3.com"
  ],
  "maxConcurrency": 5,
  "usePlaywrightFallback": true,
  "probeApiEndpoints": true
}
```

### Lead Generation (Find WordPress Sites)

```json
{
  "urls": ["https://site1.com", "https://site2.com"],
  "probeApiEndpoints": true,
  "usePlaywrightFallback": false
}
```

## 🆘 Troubleshooting

### Common Issues

**Detection Incomplete**
- Enable `usePlaywrightFallback: true` for SPA sites
- Some sites may block automated detection
- Try enabling proxy configuration

**Timeout Errors**
- Increase `timeout` value
- Reduce `maxConcurrency`
- Check if site is accessible

**WAF Blocking**
- Enable Apify Proxy
- Reduce request frequency
- Some WAFs may block all automated access

## 📄 License & Terms

This actor analyzes publicly accessible website information in accordance with ethical web scraping practices and applicable regulations.

---

**Keywords**: tech stack detection, technology scanner, framework detection, CMS detection, WAF detection, website analysis, technology research, competitor analysis