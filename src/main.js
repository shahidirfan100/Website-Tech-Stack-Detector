// Website Tech Stack Scanner - Enhanced Detection with Advanced Algorithms
import { Actor, log } from 'apify';
import { CheerioCrawler, PlaywrightCrawler, Dataset, gotScraping } from 'crawlee';
import { load as cheerioLoad } from 'cheerio';

// Extended API endpoints with better coverage
const API_ENDPOINTS = [
    '/api', '/api/v1', '/api/v2', '/api/v3',
    '/graphql', '/graphql/',
    '/_next/static', '/__nextjs_original-stack-frame',
    '/wp-json', '/wp-json/wp/v2', '/wp-admin',
    '/admin', '/admin/', '/administrator',
    '/_nuxt', '/_nuxt/static',
    '/.well-known', '/robots.txt', '/sitemap.xml',
    '/rest', '/rest/api', '/rest/v1',
    '/ajax', '/api/ajax',
    '/dnn',  // DNN CMS
    '/joomla', '/index.php?format=json',
    '/umbraco', '/umbraco/api',
    '/sitecore', '/api/sitecore',
    '/asp.net', '/.net',
];

// Enhanced WAF detection patterns
const WAF_PATTERNS = {
    cloudflare: {
        headers: ['cf-ray', 'cf-cache-status', '__cfduid', 'cf-request-id'],
        cookies: ['__cfduid', '__cf_bm', '__cfwaf'],
        server: /cloudflare/i,
        html: /cloudflare|cf-html|cf-error/i,
    },
    akamai: {
        headers: ['akamai-origin-hop', 'akamai-grn', 'akamai-request-bc', 'x-akamai-transformed'],
        server: /akamaighost|akamaitechnologies/i,
    },
    imperva: {
        headers: ['x-cdn', 'x-iinfo', 'x-originating-ip'],
        cookies: ['incap_ses', 'visid_incap', '__incap_0'],
        html: /incapsula|imperva/i,
    },
    perimeterx: {
        cookies: ['_px3', '_px2', '_pxvid', '_pxAppId'],
        headers: ['x-px-authorization'],
    },
    kasada: {
        cookies: ['x-kpsdk-ct', 'x-kpsdk-cd', 'kas.u'],
    },
    datadome: {
        cookies: ['datadome', '__dd_btid'],
        headers: ['x-datadome-cid'],
    },
    awswaf: {
        headers: ['x-amzn-waf-action', 'x-amzn-waf-flags'],
    },
    modsecurity: {
        headers: ['mod-security'],
        html: /modsecurity|mod_security/i,
    },
};

// Expanded technology patterns with better detection
const TECH_PATTERNS = {
    // Frontend Frameworks
    react: {
        script: /react[@\-.].*\.js|react\.production|react\.development/i,
        meta: [{ name: 'generator', content: /react/i }],
        window: ['React', '__REACT_DEVTOOLS_GLOBAL_HOOK__', '__REACT_PROFILER_ENABLED__'],
        html: [/<div[^>]+id=["']root["']/i, /ReactDOM\.render|ReactDOM\.createRoot/i],
        cdn: ['unpkg.com/react', 'cdnjs.com/ajax/libs/react'],
    },
    vue: {
        script: /vue[@\-.].*\.js|vue\.global|vue\.esm/i,
        window: ['Vue', '__VUE__', '__VUE_DEVTOOLS_GLOBAL_HOOK__'],
        html: [/data-v-[a-f0-9]{8}/, /v-if|v-for|v-bind|v-on/i],
        cdn: ['unpkg.com/vue', 'cdn.jsdelivr.net/npm/vue'],
    },
    angular: {
        script: /angular[@\-.].*\.js|angular\.js/i,
        window: ['ng', 'angular', 'getAllAngularRootElements', 'ng.probe'],
        html: [/<[^>]+ng-[a-z\-]+/, /ng-app|ng-controller|ng-module/i],
        meta: [{ name: 'generator', content: /angular/i }],
    },
    svelte: {
        script: /svelte[@\-.].*\.js/i,
        html: [/svelte-[a-z0-9]+/, /hidden={true}/i],
        window: ['__SVELTE__'],
    },
    nextjs: {
        script: /_next\/static|__NEXT_DATA__|next\/image/i,
        meta: [{ name: 'next-head-count' }, { name: 'next-size-adjust' }],
        html: [/<script[^>]+_next\/static/i, /__NEXT_DATA__/],
        window: ['__NEXT_DATA__', '__NEXT_ROUTER_READYSTATE__'],
        headers: { 'x-nextjs': /.+/ },
    },
    nuxtjs: {
        script: /_nuxt\/|nuxt\.app/i,
        window: ['$nuxt', '__NUXT__', '__NUXT_STRAPI__'],
        html: [/<div[^>]+id=["']__nuxt/i, /__NUXT__/],
    },
    gatsby: {
        meta: [{ name: 'generator', content: /gatsby/i }],
        html: [/<div[^>]+id=["']___gatsby/i, /gatsby-focus-wrapper/],
        window: ['__GATSBY__', '___GATSBY_PLUGIN_INIT'],
    },
    remix: {
        script: /remix|@remix-run/i,
        window: ['__remixContext', '__remixRouteModules'],
        html: /remix-route|remix-page/i,
    },
    astro: {
        script: /astro|astro\.default/i,
        html: /astro-root|astro-island/i,
        window: ['__astro'],
    },
    
    // Backend & CMS
    wordpress: {
        meta: [{ name: 'generator', content: /wordpress/i }],
        html: [/wp-content|wp-includes|wordpress/i, /\/wp-json\//],
        endpoints: ['/wp-json/wp/v2'],
        script: /wp-emoji|wp-admin|/i,
    },
    drupal: {
        meta: [{ name: 'generator', content: /drupal/i }],
        html: [/Drupal\.settings|drupal\.org/i, /sites\/default\/files/],
        endpoints: ['/jsonapi'],
    },
    joomla: {
        meta: [{ name: 'generator', content: /joomla/i }],
        html: [/\/components\/com_|\/modules\/mod_|joomla/i],
        endpoints: ['/index.php?option=com_api'],
    },
    shopify: {
        html: [/cdn\.shopify\.com|shopify-buy\.js|Shopify\..*=/i],
        headers: { 'x-shopify-stage': /.+/ },
        script: /Shopify\.shop|Shopify\.theme/i,
    },
    magento: {
        html: [/Mage\.Cookies|magento\.com|\/media\/|\/skin\/|Magento\./i],
        script: /mage\/|magento|/i,
        meta: [{ name: 'generator', content: /magento/i }],
    },
    wix: {
        html: [/wix\.com|wixstatic|wix_|/i],
        script: /wix|wixCode|/i,
    },
    squarespace: {
        meta: [{ name: 'generator', content: /squarespace/i }],
        html: /squarespace|sqs\-/i,
    },
    weebly: {
        script: /weebly|/i,
        html: /weebly\.com|weebly\-/i,
    },
    typo3: {
        meta: [{ name: 'generator', content: /typo3/i }],
        html: /typo3|\/typo3/i,
    },
    
    // UI Frameworks & CSS
    bootstrap: {
        script: /bootstrap[@\-.].*\.js/i,
        link: /bootstrap[@\-.].*\.css/i,
        html: [/class=["'][^"']*\bbtn\b[^"']*["']/, /class=["'][^"']*\bcontainer\b[^"']*["']/],
    },
    tailwind: {
        link: /tailwindcss|tailwind\.css/i,
        script: /tailwind/i,
        html: [/class=["'][^"']*\b(flex|grid|p-\d|m-\d|w-\d|h-\d)/],
    },
    materialui: {
        script: /@mui\/material|material\-ui/i,
        html: /MuiButton|MuiPaper|MuiTypography|MuiContainer/i,
    },
    bulma: {
        link: /bulma\.css|bulma\/css/i,
        html: /class=["'][^"']*\b(button|box|container|column)\b[^"']*["']/,
    },
    foundation: {
        script: /foundation[@\-.].*\.js/i,
        link: /foundation[@\-.].*\.css/i,
    },
    semanticui: {
        script: /semantic[@\-.]ui.*\.js/i,
        link: /semantic[@\-.]ui.*\.css/i,
    },
    
    // JavaScript Libraries
    jquery: {
        script: /jquery[@\-.].*\.js/i,
        window: ['jQuery', '$'],
    },
    lodash: {
        script: /lodash[@\-.].*\.js/i,
        window: ['_'],
    },
    underscore: {
        script: /underscore[@\-.].*\.js/i,
        window: ['_'],
    },
    momentjs: {
        script: /moment[@\-.].*\.js/i,
        window: ['moment'],
    },
    d3: {
        script: /d3[@\-.].*\.js/i,
        window: ['d3'],
    },
    threejs: {
        script: /three[@\-.].*\.js|three\.min\.js/i,
        window: ['THREE'],
    },
    
    // Analytics & Monitoring
    googleanalytics: {
        script: [/google\-analytics\.com|googletagmanager\.com\/gtag|analytics\.js/i, /ga\(|gtag\(/i],
        html: /gtag\(|_gaq|ga\(/i,
    },
    gtm: {
        script: /googletagmanager\.com\/gtm\.js/i,
        html: /<!-- Google Tag Manager -->|noscript.*googletagmanager/i,
    },
    hotjar: {
        script: /static\.hotjar\.com|hj\-*script/i,
        window: ['hj', 'hjSiteId'],
    },
    mixpanel: {
        script: /cdn\.mxpnl\.com|mixpanel\.com\/track/i,
        window: ['mixpanel'],
    },
    segment: {
        script: /segment\.com|analytics\.js/i,
        window: ['analytics'],
    },
    amplitude: {
        script: /cdn\.amplitude\.com/i,
        window: ['amplitude'],
    },
    intercom: {
        script: /intercom\.io|app\.intercom\.com/i,
        window: ['Intercom', 'intercomSettings'],
    },
    sentry: {
        script: /sentry\.io|@sentry/i,
        window: ['Sentry'],
    },
    
    // Hosting & Deployment
    vercel: {
        headers: { 'x-vercel-id': /.+/, 'x-vercel-cache': /.+/, 'x-vercel-skew': /.+/ },
        html: /vercel|vercel\.com/i,
    },
    netlify: {
        headers: { 'x-nf-request-id': /.+/, 'x-nf-cache': /.+/ },
        html: /netlify|netlify\.com/i,
        meta: [{ name: 'generator', content: /netlify/i }],
    },
    heroku: {
        headers: { 'x-heroku': /.+/ },
        html: /heroku\.com/i,
    },
    digitalocean: {
        headers: { 'server': /digitalocean|DO-AppPlatform/i },
    },
    aws: {
        headers: { 'server': /amazon|aws|elasticloadbalancing/i },
        html: /amazonaws\.com|aws\.amazon\.com/i,
    },
    
    // CDN
    cloudflare: {
        headers: { 'cf-ray': /.+/, 'cf-cache-status': /.+/ },
    },
    cloudfront: {
        headers: { 'x-amz-cf-pop': /.+/, 'x-amz-cf-id': /.+/ },
    },
    fastly: {
        headers: { 'x-served-by': /cache-.*\.fastly\.net/i, 'x-fastly-request-id': /.+/ },
    },
    akamai_cdn: {
        headers: { 'x-akamai-transformed': /.+/ },
    },
};

/**
 * Deduplicate array of strings with case-insensitive comparison
 */
function deduplicateArray(arr) {
    if (!Array.isArray(arr)) return [];
    const seen = new Set();
    return arr.filter(item => {
        const lower = (item || '').toLowerCase();
        if (seen.has(lower)) return false;
        seen.add(lower);
        return true;
    });
}

/**
 * Extract version from text with advanced regex
 */
function extractVersion(text) {
    if (!text) return null;
    // Try to extract semantic versioning: X.Y.Z
    const versionPatterns = [
        /v?(\d+\.\d+\.\d+(?:\-[a-zA-Z0-9\.]+)?(?:\+[a-zA-Z0-9\.]+)?)/,
        /(\d+\.\d+\.\d+)/,
        /v(\d+\.\d+)/,
        /(\d+\.\d+)/,
    ];
    
    for (const pattern of versionPatterns) {
        const match = text.match(pattern);
        if (match) return match[1];
    }
    return null;
}

/**
 * Advanced WAF detection with scoring
 */
function detectWAF(headers, cookies, html) {
    const wafScores = {};
    
    for (const [name, patterns] of Object.entries(WAF_PATTERNS)) {
        let score = 0;
        
        // Check headers (weight: 3)
        if (patterns.headers) {
            const matches = patterns.headers.filter(h => headers[h.toLowerCase()] !== undefined).length;
            score += matches * 3;
        }
        
        // Check cookies (weight: 2)
        if (patterns.cookies) {
            const matches = patterns.cookies.filter(c => 
                cookies.some(cookie => cookie.toLowerCase().startsWith(c.toLowerCase()))
            ).length;
            score += matches * 2;
        }
        
        // Check server header (weight: 2)
        if (patterns.server) {
            const server = headers['server'] || '';
            if (patterns.server.test(server)) score += 2;
        }
        
        // Check HTML patterns (weight: 1)
        if (patterns.html && html) {
            if (patterns.html.test(html)) score += 1;
        }
        
        if (score > 0) {
            wafScores[name] = score;
        }
    }
    
    if (Object.keys(wafScores).length === 0) return null;
    
    const topWaf = Object.entries(wafScores).reduce((a, b) => a[1] > b[1] ? a : b);
    return {
        name: topWaf[0].charAt(0).toUpperCase() + topWaf[0].slice(1),
        confidence: topWaf[1] >= 5 ? 'high' : topWaf[1] >= 3 ? 'medium' : 'low',
        score: topWaf[1],
    };
}

/**
 * Advanced technology detection with multi-source validation
 */
function analyzeStaticResponse(html, headers, url) {
    const $ = cheerioLoad(html);
    const technologies = {
        frontend: [],
        backend: [],
        cms: [],
        analytics: [],
        hosting: [],
        cdn: [],
        libraries: [],
    };
    
    const detectionSources = {};
    
    // Detect technologies with scoring
    for (const [techName, patterns] of Object.entries(TECH_PATTERNS)) {
        let confidence = 0;
        let version = null;
        const sources = [];
        
        // Check scripts (weight: 3)
        if (patterns.script) {
            const scriptPatterns = Array.isArray(patterns.script) ? patterns.script : [patterns.script];
            $('script').each((_, el) => {
                const src = $(el).attr('src') || '';
                const content = $(el).html() || '';
                const fullContent = src + content;
                
                scriptPatterns.forEach(p => {
                    if (p.test(fullContent)) {
                        confidence += 3;
                        sources.push('script');
                        if (!version) version = extractVersion(fullContent);
                    }
                });
            });
        }
        
        // Check links (weight: 2)
        if (patterns.link) {
            const linkPatterns = Array.isArray(patterns.link) ? patterns.link : [patterns.link];
            $('link[rel="stylesheet"]').each((_, el) => {
                const href = $(el).attr('href') || '';
                linkPatterns.forEach(p => {
                    if (p.test(href)) {
                        confidence += 2;
                        sources.push('stylesheet');
                        if (!version) version = extractVersion(href);
                    }
                });
            });
        }
        
        // Check meta tags (weight: 2)
        if (patterns.meta) {
            patterns.meta.forEach(meta => {
                const content = $(`meta[name="${meta.name}"]`).attr('content') || '';
                if (meta.content && meta.content.test(content)) {
                    confidence += 2;
                    sources.push('meta');
                }
            });
        }
        
        // Check HTML patterns (weight: 2)
        if (patterns.html) {
            const htmlPatterns = Array.isArray(patterns.html) ? patterns.html : [patterns.html];
            htmlPatterns.forEach(p => {
                if (p.test(html)) {
                    confidence += 2;
                    sources.push('html');
                }
            });
        }
        
        // Check headers (weight: 2)
        if (patterns.headers) {
            Object.entries(patterns.headers).forEach(([headerName, headerPattern]) => {
                const headerValue = headers[headerName.toLowerCase()] || '';
                if (headerPattern.test(headerValue)) {
                    confidence += 2;
                    sources.push('header');
                }
            });
        }
        
        // Check CDN (weight: 1)
        if (patterns.cdn) {
            patterns.cdn.forEach(cdn => {
                $('script').each((_, el) => {
                    const src = $(el).attr('src') || '';
                    if (src.includes(cdn)) {
                        confidence += 1;
                        sources.push('cdn');
                    }
                });
            });
        }
        
        // Check window globals (weight: 1) - flagged for browser detection
        if (patterns.window) {
            // Store for later browser-based detection
            if (!detectionSources[techName]) {
                detectionSources[techName] = { sources, confidence, version };
            }
        }
        
        if (confidence > 0) {
            const techString = version ? `${techName} ${version}` : techName;
            
            // Categorize technology
            if (['react', 'vue', 'angular', 'svelte', 'nextjs', 'nuxtjs', 'gatsby', 'remix', 'astro'].includes(techName)) {
                if (!technologies.frontend.includes(techString)) {
                    technologies.frontend.push(techString);
                }
            } else if (['wordpress', 'drupal', 'joomla', 'shopify', 'magento', 'wix', 'squarespace', 'weebly', 'typo3'].includes(techName)) {
                if (!technologies.cms.includes(techString)) {
                    technologies.cms.push(techString);
                }
            } else if (['googleanalytics', 'gtm', 'hotjar', 'mixpanel', 'segment', 'amplitude', 'intercom', 'sentry'].includes(techName)) {
                if (!technologies.analytics.includes(techString)) {
                    technologies.analytics.push(techString);
                }
            } else if (['vercel', 'netlify', 'heroku', 'digitalocean', 'aws'].includes(techName)) {
                if (!technologies.hosting.includes(techString)) {
                    technologies.hosting.push(techString);
                }
            } else if (['cloudflare', 'cloudfront', 'fastly', 'akamai_cdn'].includes(techName)) {
                if (!technologies.cdn.includes(techString)) {
                    technologies.cdn.push(techString);
                }
            } else {
                if (!technologies.libraries.includes(techString)) {
                    technologies.libraries.push(techString);
                }
            }
        }
    }
    
    // Deduplicate all arrays
    Object.keys(technologies).forEach(key => {
        technologies[key] = deduplicateArray(technologies[key]);
    });
    
    // Extract structured data
    const structuredData = [];
    $('script[type="application/ld+json"]').each((_, el) => {
        try {
            const json = JSON.parse($(el).html());
            structuredData.push(json);
        } catch (e) {
            // Invalid JSON
        }
    });
    
    return { technologies, structuredData };
}

/**
 * Advanced browser detection
 */
async function extractBrowserTechnologies(page) {
    return await page.evaluate(() => {
        const detected = [];
        const win = window;
        
        const checks = {
            'React': ['React', '__REACT_DEVTOOLS_GLOBAL_HOOK__', '__REACT_PROFILER_ENABLED__'],
            'Vue': ['Vue', '__VUE__', '__VUE_DEVTOOLS_GLOBAL_HOOK__'],
            'Angular': ['ng', 'angular', 'getAllAngularRootElements', 'ng.probe'],
            'jQuery': ['jQuery', '$'],
            'Next.js': ['__NEXT_DATA__', '__NEXT_ROUTER_READYSTATE__'],
            'Nuxt.js': ['$nuxt', '__NUXT__', '__NUXT_STRAPI__'],
            'Svelte': ['__SVELTE__'],
            'Astro': ['__astro'],
            'Lodash': ['_'],
            'Moment.js': ['moment'],
            'D3': ['d3'],
            'Three.js': ['THREE'],
            'Mixpanel': ['mixpanel'],
            'Sentry': ['Sentry'],
            'Intercom': ['Intercom'],
            'Hotjar': ['hj', 'hjSiteId'],
            'Amplitude': ['amplitude'],
        };
        
        for (const [name, props] of Object.entries(checks)) {
            for (const prop of props) {
                try {
                    if (win[prop] !== undefined && win[prop] !== null) {
                        detected.push(name);
                        break;
                    }
                } catch (e) {
                    // Skip if accessing property throws
                }
            }
        }
        
        return [...new Set(detected)];
    });
}

/**
 * Probe API endpoints with advanced detection
 */
async function probeApiEndpoints(baseUrl, proxyUrl) {
    const discovered = {
        graphql: false,
        rest: false,
        endpoints: [],
    };
    
    for (const endpoint of API_ENDPOINTS) {
        try {
            const url = new URL(endpoint, baseUrl).href;
            const response = await gotScraping({
                url,
                method: 'GET',
                proxyUrl,
                timeout: { request: 5000 },
                throwHttpErrors: false,
                retry: { limit: 0 },
            });
            
            if (response.statusCode < 400) {
                discovered.endpoints.push(endpoint);
                
                if (endpoint.includes('graphql')) {
                    discovered.graphql = true;
                }
                
                const contentType = response.headers['content-type'] || '';
                if (contentType.includes('application/json')) {
                    discovered.rest = true;
                }
            }
        } catch (e) {
            // Endpoint not accessible
        }
    }
    
    // Deduplicate endpoints
    discovered.endpoints = deduplicateArray(discovered.endpoints);
    
    return discovered;
}

/**
 * Clean and deduplicate final result
 */
function deduplicateResult(result) {
    if (result.technologies) {
        Object.keys(result.technologies).forEach(key => {
            result.technologies[key] = deduplicateArray(result.technologies[key]);
        });
    }
    
    if (result.apis?.endpoints) {
        result.apis.endpoints = deduplicateArray(result.apis.endpoints);
    }
    
    return result;
}

// Main Actor
await Actor.init();

try {
    const input = await Actor.getInput() || {};
    const {
        urls = [],
        maxConcurrency = 5,
        usePlaywrightFallback = true,
        probeApiEndpoints: shouldProbeApi = true,
        timeout = 30,
        proxyConfiguration,
    } = input;
    
    if (!urls || urls.length === 0) {
        throw new Error('No URLs provided.');
    }
    
    log.info(`🚀 Starting tech stack scan for ${urls.length} URL(s)`);
    
    const proxyConfig = proxyConfiguration 
        ? await Actor.createProxyConfiguration(proxyConfiguration)
        : undefined;
    
    const startTime = Date.now();
    let processedCount = 0;
    const results = [];
    
    // Phase 1: CheerioCrawler for fast static analysis
    const cheerioCrawler = new CheerioCrawler({
        maxConcurrency,
        requestHandlerTimeoutSecs: timeout,
        proxyConfiguration: proxyConfig,
        
        async requestHandler({ request, response, body, $ }) {
            const url = request.url;
            
            try {
                const headers = response.headers || {};
                const cookies = headers['set-cookie'] || [];
                
                // Advanced WAF detection
                const waf = detectWAF(headers, Array.isArray(cookies) ? cookies : [cookies], body);
                
                // Advanced technology analysis
                const { technologies, structuredData } = analyzeStaticResponse(body, headers, url);
                
                const serverInfo = {
                    software: headers['server'] || 'Unknown',
                    poweredBy: headers['x-powered-by'] || null,
                };
                
                // API probing
                let apis = { graphql: false, rest: false, endpoints: [] };
                if (shouldProbeApi) {
                    const proxyUrl = proxyConfig ? await proxyConfig.newUrl() : undefined;
                    apis = await probeApiEndpoints(url, proxyUrl);
                }
                
                const result = {
                    url,
                    status: 'success',
                    technologies,
                    waf: waf ? { detected: true, provider: waf.name, confidence: waf.confidence, score: waf.score } : { detected: false },
                    apis,
                    metadata: {
                        title: $('title').text() || null,
                        description: $('meta[name="description"]').attr('content') || null,
                    },
                    server: serverInfo,
                    detectionMethod: 'static',
                    scannedAt: new Date().toISOString(),
                };
                
                // Deduplicate result
                const cleanResult = deduplicateResult(result);
                
                results.push(cleanResult);
                await Dataset.pushData(cleanResult);
                processedCount++;
                
                const techCount = Object.values(technologies).flat().length;
                log.info(`✅ ${url} - Found ${techCount} technologies`);
                
            } catch (error) {
                log.error(`❌ Error analyzing ${url}: ${error.message}`);
                const failedResult = { url, status: 'failed', error: error.message, scannedAt: new Date().toISOString() };
                results.push(failedResult);
                await Dataset.pushData(failedResult);
            }
        },
        
        failedRequestHandler({ request, error }) {
            log.error(`Request failed: ${request.url}`);
        },
    });
    
    await cheerioCrawler.run(urls.map(url => ({ url })));
    
    // Phase 2: PlaywrightCrawler for SPA sites
    if (usePlaywrightFallback) {
        const spaUrls = results
            .filter(r => r.status === 'success' && Object.values(r.technologies || {}).flat().length === 0)
            .map(r => r.url);
        
        if (spaUrls.length > 0) {
            log.info(`🌐 ${spaUrls.length} SPAs detected, using Playwright...`);
            
            const playwrightCrawler = new PlaywrightCrawler({
                maxConcurrency: Math.max(1, Math.floor(maxConcurrency / 2)),
                requestHandlerTimeoutSecs: timeout,
                proxyConfiguration: proxyConfig,
                launchContext: { launchOptions: { headless: true } },
                
                async requestHandler({ request, page, response }) {
                    const url = request.url;
                    
                    try {
                        await page.waitForLoadState('networkidle', { timeout: timeout * 1000 });
                        
                        const html = await page.content();
                        const headers = response ? response.headers() : {};
                        const browserTechs = await extractBrowserTechnologies(page);
                        const { technologies, structuredData } = analyzeStaticResponse(html, headers, url);
                        
                        // Merge with deduplication
                        browserTechs.forEach(tech => {
                            if (!technologies.frontend.includes(tech)) {
                                technologies.frontend.push(tech);
                            }
                        });
                        
                        const idx = results.findIndex(r => r.url === url);
                        if (idx !== -1) {
                            results[idx].technologies = technologies;
                            results[idx].detectionMethod = 'browser';
                            const cleanResult = deduplicateResult(results[idx]);
                            await Dataset.pushData(cleanResult);
                            log.info(`✅ Updated ${url} with browser detection`);
                        }
                        
                    } catch (error) {
                        log.error(`Browser error for ${url}`);
                    }
                },
            });
            
            await playwrightCrawler.run(spaUrls.map(url => ({ url })));
        }
    }
    
    const totalTime = (Date.now() - startTime) / 1000;
    
    log.info('='.repeat(70));
    log.info('📊 TECH STACK SCANNER - ENHANCED DETECTION COMPLETE');
    log.info('='.repeat(70));
    log.info(`✅ URLs analyzed: ${processedCount}/${urls.length}`);
    log.info(`⏱️  Total runtime: ${totalTime.toFixed(2)}s`);
    log.info(`⚡ Performance: ${(processedCount / totalTime).toFixed(2)} URLs/second`);
    log.info('='.repeat(70));
    
    if (processedCount === 0) {
        await Actor.fail('No results produced');
    } else {
        log.info(`✅ SUCCESS: Analyzed ${processedCount} website(s) with advanced detection`);
        await Actor.setValue('OUTPUT_SUMMARY', {
            urlsAnalyzed: processedCount,
            runtime: totalTime,
            success: true,
        });
    }
    
} catch (error) {
    log.error(`❌ CRITICAL ERROR: ${error.message}`);
    log.exception(error, 'Actor failed');
    throw error;
} finally {
    await Actor.exit();
}
