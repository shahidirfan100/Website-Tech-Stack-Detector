// Website Tech Stack Scanner - Enhanced Detection with Advanced Algorithms
import { Actor, log } from 'apify';
import { CheerioCrawler, PlaywrightCrawler, Dataset, gotScraping } from 'crawlee';
import { load as cheerioLoad } from 'cheerio';

// Essential API endpoints for fast detection
const API_ENDPOINTS = [
    '/api',
    '/graphql',
    '/_next/static',
    '/wp-json/wp/v2',
    '/_nuxt',
    '/robots.txt',
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
        script: /@angular\/core|angular\.min\.js|angular\.js/i,
        window: ['ng', 'getAllAngularRootElements'],
        html: [/ng-version=["']\d+\.\d+/i, /_nghost-|_ngcontent-|<app-root/i],
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
        html: [/wp-content\/themes\//i, /wp-content\/plugins\//i, /wp-includes\//i],
        script: /wp-emoji-release\.min\.js|wp-admin/i,
        link: /wp-content\/themes\/|wp-includes\/css\//i,
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
        html: [/Mage\.Cookies/i, /var BLANK_URL.*checkout\/cart/i],
        script: /mage\/cookies\.js|magento/i,
        meta: [{ name: 'generator', content: /magento/i }],
        window: ['Mage'],
    },
    wix: {
        html: [/static\.parastorage\.com|wixstatic\.com/i],
        script: /static\.wixstatic\.com|wix-code-viewer/i,
        meta: [{ name: 'generator', content: /wix\.com/i }],
    },
    squarespace: {
        meta: [{ name: 'generator', content: /squarespace/i }],
        html: /squarespace|sqs\-/i,
    },
    weebly: {
        script: /cdn\d+\.editmysite\.com|weebly\.com\/weebly/i,
        html: /class=["']weebly-/i,
        meta: [{ name: 'generator', content: /weebly/i }],
    },
    typo3: {
        meta: [{ name: 'generator', content: /typo3/i }],
        html: /typo3|\/typo3/i,
    },
    
    // UI Frameworks & CSS
    bootstrap: {
        script: /bootstrap[@\-.]\.min\.js|bootstrap[@\-.].*\.bundle/i,
        link: /bootstrap[@\-.].*\.min\.css|bootstrap[@\-.].*\.css/i,
        html: [/class=["'][^"']*(btn-primary|btn-secondary|btn-success|btn-danger)[^"']*["']/i, /class=["'][^"']*(container-fluid|row|col-)/i],
    },
    tailwind: {
        link: /tailwindcss|tailwind.*\.css/i,
        script: /cdn\.tailwindcss\.com/i,
        html: [/class=["'][^"']*(bg-gradient-|from-|to-|via-)[^"']*["']/i, /class=["'][^"']*(hover:|focus:|active:|group-)/i],
    },
    materialui: {
        script: /@mui\/material|material\-ui/i,
        html: /MuiButton|MuiPaper|MuiTypography|MuiContainer/i,
    },
    bulma: {
        link: /bulma(@[\d.]+)?\/css\/bulma|bulma\.min\.css/i,
        html: [/class=["'][^"']*(is-primary|is-link|is-info|is-success)[^"']*["']/i, /class=["'][^"']*(hero|card|panel|notification|message)\b/i],
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

// Technology categories and thresholds to reduce false positives
const TECH_CATEGORIES = {
    frontend: ['react', 'vue', 'angular', 'svelte', 'nextjs', 'nuxtjs', 'gatsby', 'remix', 'astro'],
    cms: ['wordpress', 'drupal', 'joomla', 'shopify', 'magento', 'wix', 'squarespace', 'weebly', 'typo3'],
    analytics: ['googleanalytics', 'gtm', 'hotjar', 'mixpanel', 'segment', 'amplitude', 'intercom', 'sentry'],
    hosting: ['vercel', 'netlify', 'heroku', 'digitalocean', 'aws'],
    cdn: ['cloudflare', 'cloudfront', 'fastly', 'akamai_cdn'],
};

const MIN_CONFIDENCE_BY_CATEGORY = {
    cms: 3,
    frontend: 2,
    analytics: 2,
    hosting: 2,
    cdn: 2,
    libraries: 2,
};

// Inference hints to produce a human-friendly final verdict
const STACK_INFERENCES = {
    wordpress: { languages: ['PHP'], databases: ['MySQL/MariaDB'] },
    drupal: { languages: ['PHP'], databases: ['MySQL/MariaDB', 'PostgreSQL'] },
    joomla: { languages: ['PHP'], databases: ['MySQL/MariaDB'] },
    magento: { languages: ['PHP'], databases: ['MySQL/MariaDB'] },
    shopify: { languages: ['Ruby on Rails'], databases: ['Shopify managed store'] },
    wix: { languages: ['Wix platform'], databases: ['Wix Data'] },
    squarespace: { languages: ['Squarespace platform'], databases: ['Squarespace Data'] },
    weebly: { languages: ['Weebly platform'], databases: ['Weebly Data'] },
    typo3: { languages: ['PHP'], databases: ['MySQL/MariaDB'] },
    nextjs: { languages: ['Node.js'] },
    nuxtjs: { languages: ['Node.js'] },
    react: { languages: ['JavaScript/TypeScript'] },
    vue: { languages: ['JavaScript/TypeScript'] },
    angular: { languages: ['JavaScript/TypeScript'] },
    svelte: { languages: ['JavaScript/TypeScript'] },
    astro: { languages: ['JavaScript/TypeScript'] },
};

// Human readable labels
const DISPLAY_NAMES = {
    nextjs: 'Next.js',
    nuxtjs: 'Nuxt.js',
    gatsby: 'Gatsby',
    remix: 'Remix',
    astro: 'Astro',
    jquery: 'jQuery',
    lodash: 'Lodash',
    momentjs: 'Moment.js',
    googleanalytics: 'Google Analytics',
    gtm: 'Google Tag Manager',
    materialui: 'Material UI',
    aws: 'AWS',
    akamai_cdn: 'Akamai CDN',
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

function humanizeTechName(name) {
    if (!name) return '';
    const lower = name.toLowerCase();
    if (DISPLAY_NAMES[lower]) return DISPLAY_NAMES[lower];
    return lower
        .split(/[_-]/)
        .map(part => part.charAt(0).toUpperCase() + part.slice(1))
        .join(' ');
}

function formatTechName(name, version) {
    return version ? `${name} ${version}` : name;
}

function getCategoryForTech(techName) {
    const lower = techName.toLowerCase();
    for (const [category, names] of Object.entries(TECH_CATEGORIES)) {
        if (names.includes(lower)) return category;
    }
    return 'libraries';
}

function confidenceFromScore(score) {
    if (score >= 6) return 'high';
    if (score >= 3) return 'medium';
    return 'low';
}

function mapBrowserTechToKey(displayName) {
    const normalized = (displayName || '').toLowerCase().replace(/[^a-z0-9]/g, '');
    const mapping = {
        nextjs: 'nextjs',
        nuxtjs: 'nuxtjs',
        react: 'react',
        vue: 'vue',
        angular: 'angular',
        svelte: 'svelte',
        astro: 'astro',
        jquery: 'jquery',
        lodash: 'lodash',
        momentjs: 'momentjs',
        d3: 'd3',
        threejs: 'threejs',
        mixpanel: 'mixpanel',
        sentry: 'sentry',
        intercom: 'intercom',
        hotjar: 'hotjar',
        amplitude: 'amplitude',
    };
    return mapping[normalized] || null;
}

function buildVerdict(technologies, techMatches, waf, serverInfo) {
    const pickTop = (category) => {
        const candidates = Object.entries(techMatches || {}).filter(([, meta]) => meta.category === category);
        if (candidates.length === 0) return null;
        candidates.sort((a, b) => b[1].confidence - a[1].confidence);
        const [key, meta] = candidates[0];
        return {
            key,
            displayName: meta.displayName || humanizeTechName(key),
            version: meta.version || null,
            confidence: meta.confidence,
        };
    };

    const primary = {
        cms: pickTop('cms'),
        frontend: pickTop('frontend'),
        hosting: pickTop('hosting'),
        cdn: pickTop('cdn'),
    };

    const inferred = {
        languages: [],
        databases: [],
    };

    const addInference = (key) => {
        if (!key) return;
        const lower = key.toLowerCase();
        const inference = STACK_INFERENCES[lower];
        if (inference?.languages) inferred.languages.push(...inference.languages);
        if (inference?.databases) inferred.databases.push(...inference.databases);
    };

    addInference(primary.cms?.key);
    addInference(primary.frontend?.key);

    const serverBlob = `${serverInfo?.software || ''} ${serverInfo?.poweredBy || ''}`.toLowerCase();
    if (serverBlob.includes('php')) inferred.languages.push('PHP');
    if (serverBlob.includes('asp.net')) inferred.languages.push('.NET');
    if (serverBlob.includes('node')) inferred.languages.push('Node.js');
    if (serverBlob.includes('python')) inferred.languages.push('Python');
    if (serverBlob.includes('ruby')) inferred.languages.push('Ruby');
    if (serverBlob.includes('laravel')) inferred.languages.push('PHP');

    inferred.languages = deduplicateArray(inferred.languages);
    inferred.databases = deduplicateArray(inferred.databases);

    const summaryParts = [];
    if (primary.cms) summaryParts.push(`CMS: ${formatTechName(primary.cms.displayName, primary.cms.version)}`);
    if (primary.frontend) summaryParts.push(`Frontend: ${formatTechName(primary.frontend.displayName, primary.frontend.version)}`);
    if (primary.hosting) summaryParts.push(`Hosting: ${formatTechName(primary.hosting.displayName, primary.hosting.version)}`);
    if (primary.cdn) summaryParts.push(`CDN: ${formatTechName(primary.cdn.displayName, primary.cdn.version)}`);
    if (waf?.detected) summaryParts.push(`WAF: ${waf.provider} (${waf.confidence})`);
    if (inferred.languages.length) summaryParts.push(`Language: ${inferred.languages.join(', ')}`);
    if (inferred.databases.length) summaryParts.push(`Database: ${inferred.databases.join(', ')}`);

    const topScore = Math.max(
        primary.cms?.confidence || 0,
        primary.frontend?.confidence || 0,
        primary.hosting?.confidence || 0,
        primary.cdn?.confidence || 0,
    );

    return {
        primary,
        inferred,
        confidence: confidenceFromScore(topScore),
        summary: summaryParts.join(' | '),
    };
}

/**
 * Extract version from text with context-aware regex
 */
function extractVersion(text, techName) {
    if (!text) return null;
    
    // Look for version near technology name or in common patterns
    const contextPatterns = [
        new RegExp(`${techName}[@\/\-]v?(\\d+\.\\d+\.\\d+)`, 'i'),
        new RegExp(`${techName}[@\/\-](\\d+\.\\d+)`, 'i'),
        /\/([\d.]+)\//, // version in URL path
        /@([\d.]+)\//, // NPM version format
    ];
    
    for (const pattern of contextPatterns) {
        const match = text.match(pattern);
        if (match && match[1]) {
            const version = match[1];
            // Validate version format (must have at least X.Y)
            if (/^\d+\.\d+/.test(version)) {
                return version;
            }
        }
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
    
    const techMatches = {};
    const cmsCandidates = [];
    
    // Detect technologies with scoring
    for (const [techName, patterns] of Object.entries(TECH_PATTERNS)) {
        let confidence = 0;
        let version = null;
        const sources = new Set();
        
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
                        sources.add('script');
                        if (!version) version = extractVersion(fullContent, techName);
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
                        sources.add('stylesheet');
                        if (!version) version = extractVersion(href, techName);
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
                    sources.add('meta');
                    if (!version) version = extractVersion(content, techName);
                }
            });
        }
        
        // Check HTML patterns (weight: 2)
        if (patterns.html) {
            const htmlPatterns = Array.isArray(patterns.html) ? patterns.html : [patterns.html];
            htmlPatterns.forEach(p => {
                if (p.test(html)) {
                    confidence += 2;
                    sources.add('html');
                }
            });
        }
        
        // Check headers (weight: 2)
        if (patterns.headers) {
            Object.entries(patterns.headers).forEach(([headerName, headerPattern]) => {
                const headerValue = headers[headerName.toLowerCase()] || '';
                if (headerPattern.test(headerValue)) {
                    confidence += 2;
                    sources.add('header');
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
                        sources.add('cdn');
                    }
                });
            });
        }

        const category = getCategoryForTech(techName);
        const threshold = MIN_CONFIDENCE_BY_CATEGORY[category] || 2;
        const displayName = humanizeTechName(techName);

        if (confidence >= threshold) {
            const techString = formatTechName(displayName, version);

            if (category === 'cms') {
                cmsCandidates.push({ key: techName, displayName, confidence, version });
            } else {
                technologies[category].push(techString);
            }

            techMatches[techName] = {
                confidence,
                version,
                category,
                displayName,
                sources: Array.from(sources),
            };
        }
    }
    
    if (cmsCandidates.length > 0) {
        cmsCandidates.sort((a, b) => b.confidence - a.confidence);
        const topCMS = cmsCandidates[0];
        technologies.cms = [formatTechName(topCMS.displayName, topCMS.version)];
        techMatches[topCMS.key] = techMatches[topCMS.key] || {
            confidence: topCMS.confidence,
            version: topCMS.version,
            category: 'cms',
            displayName: topCMS.displayName,
            sources: ['html'],
        };
    }
    
    // Clean up and deduplicate all arrays
    Object.keys(technologies).forEach(key => {
        // Convert any remaining objects to strings
        if (Array.isArray(technologies[key])) {
            technologies[key] = technologies[key].map(item => 
                typeof item === 'object' ? item.displayName || item.name : item
            );
        }
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
    
    return { technologies, structuredData, techMatches };
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
 * Probe API endpoints with parallel requests (fast)
 */
async function probeApiEndpoints(baseUrl, proxyUrl) {
    const discovered = {
        graphql: false,
        rest: false,
        endpoints: [],
    };
    
    // Probe all endpoints in parallel for speed
    const probePromises = API_ENDPOINTS.map(async (endpoint) => {
        try {
            const url = new URL(endpoint, baseUrl).href;
            const response = await gotScraping({
                url,
                method: 'GET',
                proxyUrl,
                timeout: { request: 2000 }, // Fast 2s timeout
                throwHttpErrors: false,
                retry: { limit: 0 },
            });
            
            if (response.statusCode < 400) {
                return { endpoint, contentType: response.headers['content-type'] || '' };
            }
        } catch (e) {
            // Endpoint not accessible
        }
        return null;
    });
    
    const results = await Promise.all(probePromises);
    
    results.forEach(result => {
        if (result) {
            discovered.endpoints.push(result.endpoint);
            
            if (result.endpoint.includes('graphql')) {
                discovered.graphql = true;
            }
            
            if (result.contentType.includes('application/json')) {
                discovered.rest = true;
            }
        }
    });
    
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
    
    if (result.verdict?.inferred) {
        if (result.verdict.inferred.languages) {
            result.verdict.inferred.languages = deduplicateArray(result.verdict.inferred.languages);
        }
        if (result.verdict.inferred.databases) {
            result.verdict.inferred.databases = deduplicateArray(result.verdict.inferred.databases);
        }
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
        navigationTimeoutSecs: 20, // Fast navigation timeout
        maxRequestRetries: 1, // Reduce retries for speed
        proxyConfiguration: proxyConfig,
        
        async requestHandler({ request, response, body, $ }) {
            const url = request.url;
            
            try {
                const headers = response.headers || {};
                const cookies = headers['set-cookie'] || [];
                
                // Advanced WAF detection
                const waf = detectWAF(headers, Array.isArray(cookies) ? cookies : [cookies], body);
                const wafInfo = waf ? { detected: true, provider: waf.name, confidence: waf.confidence, score: waf.score } : { detected: false };
                
                // Advanced technology analysis
                const { technologies, structuredData, techMatches } = analyzeStaticResponse(body, headers, url);
                
                const serverInfo = {
                    software: headers['server'] || 'Unknown',
                    poweredBy: headers['x-powered-by'] || null,
                };
                
                // API probing with timeout protection
                let apis = { graphql: false, rest: false, endpoints: [] };
                if (shouldProbeApi) {
                    try {
                        const proxyUrl = proxyConfig ? await proxyConfig.newUrl() : undefined;
                        // Timeout API probing after 5 seconds total
                        apis = await Promise.race([
                            probeApiEndpoints(url, proxyUrl),
                            new Promise((resolve) => 
                                setTimeout(() => resolve({ graphql: false, rest: false, endpoints: [] }), 5000)
                            ),
                        ]);
                    } catch (e) {
                        log.warning(`API probing failed for ${url}: ${e.message}`);
                    }
                }
                
                const result = {
                    url,
                    status: 'success',
                    technologies,
                    waf: wafInfo,
                    apis,
                    metadata: {
                        title: $('title').text() || null,
                        description: $('meta[name="description"]').attr('content') || null,
                        structuredData,
                    },
                    server: serverInfo,
                    detectionMethod: 'static',
                    verdict: buildVerdict(technologies, techMatches, wafInfo, serverInfo),
                    detectionDetails: { matches: techMatches },
                    scannedAt: new Date().toISOString(),
                };
                
                // Deduplicate result
                const cleanResult = deduplicateResult(result);
                
                results.push(cleanResult);
                await Dataset.pushData(cleanResult);
                processedCount++;
                
                const techCount = Object.values(technologies).flat().length;
                log.info(`✅ ${url} - Found ${techCount} technologies`);
                if (cleanResult.verdict?.summary) {
                    log.info(`✅ Verdict: ${cleanResult.verdict.summary}`);
                }
                
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
                navigationTimeoutSecs: 15, // Faster navigation
                maxRequestRetries: 1, // Reduce retries
                proxyConfiguration: proxyConfig,
                launchContext: { launchOptions: { headless: true, timeout: 15000 } },
                
                async requestHandler({ request, page, response }) {
                    const url = request.url;
                    
                    try {
                        // Shorter wait time for SPA rendering
                        await page.waitForLoadState('domcontentloaded', { timeout: 10000 });
                        
                        const html = await page.content();
                        const headers = response ? response.headers() : {};
                        const browserTechs = await extractBrowserTechnologies(page);
                        const { technologies, structuredData, techMatches } = analyzeStaticResponse(html, headers, url);
                        
                        // Merge with deduplication
                        browserTechs.forEach(tech => {
                            const key = mapBrowserTechToKey(tech);
                            if (!key) return;
                            
                            const displayName = humanizeTechName(key);
                            const formatted = formatTechName(displayName, null);
                            const category = getCategoryForTech(key);
                            
                            if (category === 'frontend' && !technologies.frontend.some(item => item.toLowerCase() === formatted.toLowerCase())) {
                                technologies.frontend.push(formatted);
                            }
                            
                            const existing = techMatches[key] || { confidence: 0, version: null, category, displayName, sources: [] };
                            existing.confidence = Math.max(existing.confidence, 3);
                            existing.sources = deduplicateArray([...(existing.sources || []), 'window']);
                            techMatches[key] = existing;
                        });
                        
                        const idx = results.findIndex(r => r.url === url);
                        if (idx !== -1) {
                            const serverInfo = results[idx].server || {
                                software: headers['server'] || 'Unknown',
                                poweredBy: headers['x-powered-by'] || null,
                            };
                            const wafInfo = results[idx].waf || { detected: false };
                            
                            results[idx].technologies = technologies;
                            results[idx].metadata = { ...(results[idx].metadata || {}), structuredData };
                            results[idx].verdict = buildVerdict(technologies, techMatches, wafInfo, serverInfo);
                            results[idx].detectionDetails = { matches: techMatches };
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
