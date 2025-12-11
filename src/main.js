// Website Tech Stack Scanner - Smart Multi-Tier Detection
import { Actor, log } from 'apify';
import { CheerioCrawler, PlaywrightCrawler, Dataset, gotScraping } from 'crawlee';
import { load as cheerioLoad } from 'cheerio';

// Common API endpoints to probe
const API_ENDPOINTS = [
    '/api',
    '/api/v1',
    '/api/v2',
    '/graphql',
    '/_next/static',
    '/__nextjs_original-stack-frame',
    '/wp-json',
    '/wp-admin',
    '/admin',
    '/_nuxt',
    '/.well-known',
    '/robots.txt',
    '/sitemap.xml',
];

// WAF detection patterns
const WAF_PATTERNS = {
    cloudflare: {
        headers: ['cf-ray', 'cf-cache-status', '__cfduid'],
        cookies: ['__cfduid', '__cf_bm'],
        server: /cloudflare/i,
    },
    akamai: {
        headers: ['akamai-origin-hop', 'akamai-grn'],
        server: /akamaighost/i,
    },
    imperva: {
        headers: ['x-cdn', 'x-iinfo'],
        cookies: ['incap_ses', 'visid_incap'],
    },
    perimeterx: {
        cookies: ['_px3', '_px2', '_pxvid'],
    },
    kasada: {
        cookies: ['x-kpsdk-ct', 'x-kpsdk-cd'],
    },
    datadome: {
        cookies: ['datadome'],
        headers: ['x-datadome-cid'],
    },
};

// Technology patterns for detection
const TECH_PATTERNS = {
    // Frontend Frameworks
    react: {
        script: /react[-.].*\.js/i,
        meta: [{ name: 'generator', content: /react/i }],
        window: ['React', '__REACT_DEVTOOLS_GLOBAL_HOOK__'],
        html: /<div[^>]+id=["']root["']/i,
    },
    vue: {
        script: /vue[-.].*\.js/i,
        window: ['Vue', '__VUE__'],
        html: /data-v-[a-f0-9]{8}/i,
    },
    angular: {
        script: /angular[-.].*\.js/i,
        window: ['ng', 'angular'],
        html: /<[^>]+ng-[a-z]+=/i,
    },
    svelte: {
        script: /svelte[-.].*\.js/i,
        html: /svelte-[a-z0-9]+/i,
    },
    nextjs: {
        script: /_next\/static/i,
        meta: [{ name: 'next-head-count' }],
        html: /<script src=["']_next\/static/i,
    },
    nuxtjs: {
        script: /_nuxt\//i,
        window: ['$nuxt', '__NUXT__'],
    },
    gatsby: {
        meta: [{ name: 'generator', content: /gatsby/i }],
        html: /<div[^>]+id=["']___gatsby/i,
    },
    
    // Backend & CMS
    wordpress: {
        meta: [{ name: 'generator', content: /wordpress/i }],
        html: /wp-content|wp-includes/i,
        endpoints: ['/wp-json/wp/v2'],
    },
    drupal: {
        meta: [{ name: 'generator', content: /drupal/i }],
        html: /Drupal\.settings/i,
    },
    joomla: {
        meta: [{ name: 'generator', content: /joomla/i }],
        html: /\/components\/com_/i,
    },
    shopify: {
        html: /cdn\.shopify\.com/i,
        headers: { 'x-shopify-stage': /.+/ },
    },
    magento: {
        html: /Mage\.Cookies/i,
        script: /mage\/|magento/i,
    },
    wix: {
        html: /wix\.com/i,
        headers: { 'x-wix-request-id': /.+/ },
    },
    
    // UI Frameworks
    bootstrap: {
        script: /bootstrap[-.].*\.js/i,
        link: /bootstrap[-.].*\.css/i,
        html: /class=["'][^"']*\bbtn\b[^"']*["']/i,
    },
    tailwind: {
        link: /tailwindcss/i,
        html: /class=["'][^"']*\b(flex|grid|p-|m-|w-|h-)/i,
    },
    materialui: {
        script: /@mui\/material/i,
        html: /MuiButton|MuiPaper|MuiTypography/i,
    },
    
    // Libraries
    jquery: {
        script: /jquery[-.].*\.js/i,
        window: ['jQuery', '$'],
    },
    lodash: {
        script: /lodash[-.].*\.js/i,
        window: ['_'],
    },
    
    // Analytics
    googleanalytics: {
        script: /google-analytics\.com\/analytics\.js|googletagmanager\.com\/gtag/i,
        html: /gtag\(|ga\(/i,
    },
    gtm: {
        script: /googletagmanager\.com\/gtm\.js/i,
        html: /<!-- Google Tag Manager -->/i,
    },
    hotjar: {
        script: /static\.hotjar\.com/i,
    },
    mixpanel: {
        script: /cdn\.mxpnl\.com/i,
        window: ['mixpanel'],
    },
    
    // Hosting & CDN
    vercel: {
        headers: { 'x-vercel-id': /.+/, 'x-vercel-cache': /.+/ },
    },
    netlify: {
        headers: { 'x-nf-request-id': /.+/, 'server': /netlify/i },
    },
    cloudflare: {
        headers: { 'cf-ray': /.+/ },
    },
    fastly: {
        headers: { 'x-served-by': /cache-.*\.fastly\.net/i },
    },
};

/**
 * Detect WAF from headers and cookies
 */
function detectWAF(headers, cookies) {
    const detected = [];
    
    for (const [name, patterns] of Object.entries(WAF_PATTERNS)) {
        let found = false;
        
        // Check headers
        if (patterns.headers) {
            found = patterns.headers.some(h => 
                headers[h.toLowerCase()] !== undefined
            );
        }
        
        // Check cookies
        if (!found && patterns.cookies) {
            found = patterns.cookies.some(c => 
                cookies.some(cookie => cookie.startsWith(c))
            );
        }
        
        // Check server header
        if (!found && patterns.server) {
            const server = headers['server'] || '';
            found = patterns.server.test(server);
        }
        
        if (found) {
            detected.push({
                name: name.charAt(0).toUpperCase() + name.slice(1),
                confidence: 'high',
            });
        }
    }
    
    return detected.length > 0 ? detected[0] : null;
}

/**
 * Analyze HTTP response for technology patterns
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
    
    // Check meta tags
    const generator = $('meta[name="generator"]').attr('content') || '';
    
    // Detect technologies
    for (const [techName, patterns] of Object.entries(TECH_PATTERNS)) {
        let detected = false;
        let version = null;
        
        // Check scripts
        if (patterns.script) {
            $('script').each((_, el) => {
                const src = $(el).attr('src') || '';
                const content = $(el).html() || '';
                if (patterns.script.test(src) || patterns.script.test(content)) {
                    detected = true;
                    // Try to extract version
                    const versionMatch = (src + content).match(/[\d]+\.[\d]+\.[\d]+/);
                    if (versionMatch) version = versionMatch[0];
                }
            });
        }
        
        // Check links (stylesheets)
        if (!detected && patterns.link) {
            $('link[rel="stylesheet"]').each((_, el) => {
                const href = $(el).attr('href') || '';
                if (patterns.link.test(href)) {
                    detected = true;
                    const versionMatch = href.match(/[\d]+\.[\d]+\.[\d]+/);
                    if (versionMatch) version = versionMatch[0];
                }
            });
        }
        
        // Check meta tags
        if (!detected && patterns.meta) {
            patterns.meta.forEach(meta => {
                const content = $(`meta[name="${meta.name}"]`).attr('content') || '';
                if (meta.content && meta.content.test(content)) {
                    detected = true;
                }
            });
        }
        
        // Check HTML patterns
        if (!detected && patterns.html) {
            if (patterns.html.test(html)) {
                detected = true;
            }
        }
        
        // Check headers
        if (!detected && patterns.headers) {
            for (const [headerName, headerPattern] of Object.entries(patterns.headers)) {
                const headerValue = headers[headerName.toLowerCase()] || '';
                if (headerPattern.test(headerValue)) {
                    detected = true;
                }
            }
        }
        
        if (detected) {
            const techString = version ? `${capitalize(techName)} ${version}` : capitalize(techName);
            
            // Categorize technology
            if (['react', 'vue', 'angular', 'svelte', 'nextjs', 'nuxtjs', 'gatsby'].includes(techName)) {
                technologies.frontend.push(techString);
            } else if (['wordpress', 'drupal', 'joomla', 'shopify', 'magento', 'wix'].includes(techName)) {
                technologies.cms.push(techString);
            } else if (['googleanalytics', 'gtm', 'hotjar', 'mixpanel'].includes(techName)) {
                technologies.analytics.push(techString);
            } else if (['vercel', 'netlify'].includes(techName)) {
                technologies.hosting.push(techString);
            } else if (['cloudflare', 'fastly'].includes(techName)) {
                technologies.cdn.push(techString);
            } else if (['bootstrap', 'tailwind', 'materialui', 'jquery', 'lodash'].includes(techName)) {
                technologies.libraries.push(techString);
            }
        }
    }
    
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
 * Probe API endpoints
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
                
                // Check if it's GraphQL
                if (endpoint.includes('graphql')) {
                    discovered.graphql = true;
                }
                
                // Check content type for REST
                const contentType = response.headers['content-type'] || '';
                if (contentType.includes('application/json')) {
                    discovered.rest = true;
                }
            }
        } catch (e) {
            // Endpoint not accessible or timeout
        }
    }
    
    return discovered;
}

/**
 * Extract technologies from browser context (PlaywrightCrawler)
 */
async function extractBrowserTechnologies(page) {
    return await page.evaluate(() => {
        const detected = [];
        const win = window;
        
        // Check for global objects
        const checks = {
            'React': ['React', '__REACT_DEVTOOLS_GLOBAL_HOOK__'],
            'Vue': ['Vue', '__VUE__'],
            'Angular': ['ng', 'angular', 'getAllAngularRootElements'],
            'jQuery': ['jQuery', '$'],
            'Next.js': ['__NEXT_DATA__'],
            'Nuxt.js': ['$nuxt', '__NUXT__'],
            'Lodash': ['_'],
            'Mixpanel': ['mixpanel'],
        };
        
        for (const [name, props] of Object.entries(checks)) {
            for (const prop of props) {
                if (win[prop] !== undefined) {
                    detected.push(name);
                    break;
                }
            }
        }
        
        return [...new Set(detected)];
    });
}

/**
 * Capitalize first letter
 */
function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Main Actor initialization
 */
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
        throw new Error('No URLs provided. Please provide at least one URL in the "urls" array.');
    }
    
    log.info(`Starting tech stack scan for ${urls.length} URL(s)`);
    
    const proxyConfig = proxyConfiguration 
        ? await Actor.createProxyConfiguration(proxyConfiguration)
        : undefined;
    
    const startTime = Date.now();
    let processedCount = 0;
    const results = [];
    
    // Phase 1: Use CheerioCrawler for fast static analysis
    const cheerioCrawler = new CheerioCrawler({
        maxConcurrency,
        requestHandlerTimeoutSecs: timeout,
        proxyConfiguration: proxyConfig,
        
        async requestHandler({ request, response, body, $ }) {
            const url = request.url;
            log.info(`🔍 Analyzing ${url} (static)`);
            
            try {
                const headers = response.headers || {};
                const cookies = headers['set-cookie'] || [];
                
                // Detect WAF
                const waf = detectWAF(headers, Array.isArray(cookies) ? cookies : [cookies]);
                
                // Analyze static content
                const { technologies, structuredData } = analyzeStaticResponse(
                    body,
                    headers,
                    url
                );
                
                // Get server info
                const serverInfo = {
                    software: headers['server'] || 'Unknown',
                    poweredBy: headers['x-powered-by'] || null,
                    headers: {
                        server: headers['server'],
                        'x-powered-by': headers['x-powered-by'],
                        'content-type': headers['content-type'],
                    },
                };
                
                // Probe APIs if enabled
                let apis = { graphql: false, rest: false, endpoints: [] };
                if (shouldProbeApi) {
                    const proxyUrl = proxyConfig ? await proxyConfig.newUrl() : undefined;
                    apis = await probeApiEndpoints(url, proxyUrl);
                }
                
                const result = {
                    url,
                    status: 'success',
                    technologies,
                    waf: waf ? { detected: true, provider: waf.name, confidence: waf.confidence } : { detected: false },
                    apis,
                    metadata: {
                        title: $('title').text() || null,
                        description: $('meta[name="description"]').attr('content') || null,
                        structuredData,
                    },
                    server: serverInfo,
                    detectionMethod: 'static',
                    scannedAt: new Date().toISOString(),
                };
                
                results.push(result);
                await Dataset.pushData(result);
                processedCount++;
                
                log.info(`✅ Completed ${url} - Found ${Object.values(technologies).flat().length} technologies`);
                
            } catch (error) {
                log.error(`❌ Error analyzing ${url}: ${error.message}`);
                const failedResult = {
                    url,
                    status: 'failed',
                    error: error.message,
                    scannedAt: new Date().toISOString(),
                };
                results.push(failedResult);
                await Dataset.pushData(failedResult);
            }
        },
        
        failedRequestHandler({ request, error }) {
            log.error(`Request ${request.url} failed: ${error.message}`);
        },
    });
    
    // Process URLs with Cheerio first
    await cheerioCrawler.run(urls.map(url => ({ url })));
    
    // Phase 2: Use Playwright for sites that need browser rendering
    if (usePlaywrightFallback) {
        const spaUrls = results
            .filter(r => r.status === 'success' && Object.values(r.technologies).flat().length === 0)
            .map(r => r.url);
        
        if (spaUrls.length > 0) {
            log.info(`🌐 ${spaUrls.length} sites need browser rendering, using Playwright...`);
            
            const playwrightCrawler = new PlaywrightCrawler({
                maxConcurrency: Math.max(1, Math.floor(maxConcurrency / 2)),
                requestHandlerTimeoutSecs: timeout,
                proxyConfiguration: proxyConfig,
                launchContext: {
                    launchOptions: {
                        headless: true,
                    },
                },
                
                async requestHandler({ request, page, response }) {
                    const url = request.url;
                    log.info(`🌐 Analyzing ${url} (browser)`);
                    
                    try {
                        await page.waitForLoadState('networkidle', { timeout: timeout * 1000 });
                        
                        // Get HTML content
                        const html = await page.content();
                        const headers = response ? response.headers() : {};
                        
                        // Extract browser-based technologies
                        const browserTechs = await extractBrowserTechnologies(page);
                        
                        // Analyze with Cheerio
                        const { technologies, structuredData } = analyzeStaticResponse(html, headers, url);
                        
                        // Merge browser-detected technologies
                        browserTechs.forEach(tech => {
                            if (!technologies.frontend.includes(tech)) {
                                technologies.frontend.push(tech);
                            }
                        });
                        
                        // Update existing result
                        const existingIndex = results.findIndex(r => r.url === url);
                        if (existingIndex !== -1) {
                            results[existingIndex].technologies = technologies;
                            results[existingIndex].detectionMethod = 'browser';
                            results[existingIndex].metadata.structuredData = structuredData;
                            
                            await Dataset.pushData(results[existingIndex]);
                            log.info(`✅ Updated ${url} with browser data - Found ${Object.values(technologies).flat().length} technologies`);
                        }
                        
                    } catch (error) {
                        log.error(`❌ Browser error for ${url}: ${error.message}`);
                    }
                },
            });
            
            await playwrightCrawler.run(spaUrls.map(url => ({ url })));
        }
    }
    
    const totalTime = (Date.now() - startTime) / 1000;
    
    // Final statistics
    log.info('='.repeat(60));
    log.info('📊 TECH STACK SCANNER STATISTICS');
    log.info('='.repeat(60));
    log.info(`✅ URLs analyzed: ${processedCount}/${urls.length}`);
    log.info(`⏱️  Total runtime: ${totalTime.toFixed(2)}s`);
    log.info(`⚡ Performance: ${(processedCount / totalTime).toFixed(2)} URLs/second`);
    log.info('='.repeat(60));
    
    if (processedCount === 0) {
        log.error('❌ No URLs were successfully analyzed');
        await Actor.fail('No results produced');
    } else {
        log.info(`✅ SUCCESS: Analyzed ${processedCount} website(s)`);
        await Actor.setValue('OUTPUT_SUMMARY', {
            urlsAnalyzed: processedCount,
            runtime: totalTime,
            success: true,
        });
    }
    
} catch (error) {
    log.error(`❌ CRITICAL ERROR: ${error.message}`);
    log.exception(error, 'Actor failed with exception');
    throw error;
} finally {
    await Actor.exit();
}
