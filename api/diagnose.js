const https = require('https');
const http = require('http');
const dns = require('dns').promises;

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  
  const results = {
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    vercel_region: process.env.VERCEL_REGION || 'unknown',
    endpoints: {},
    dns: {},
    network: {},
    env_vars: {}
  };

  // Test DNS resolution for all possible Singpass domains
  const domains = [
    'stg.api.sign.singpass.gov.sg',
    'api.sign.singpass.gov.sg',
    'staging.sign.singpass.gov.sg',
    'sign.singpass.gov.sg',
    'google.com' // Control test
  ];

  for (const domain of domains) {
    try {
      const addresses = await dns.lookup(domain);
      results.dns[domain] = {
        success: true,
        address: addresses.address,
        family: addresses.family
      };
    } catch (error) {
      results.dns[domain] = {
        success: false,
        error: error.message,
        code: error.code
      };
    }
  }

  // Test TCP connectivity
  const endpoints = [
    { host: 'stg.api.sign.singpass.gov.sg', port: 443, name: 'Staging API' },
    { host: 'api.sign.singpass.gov.sg', port: 443, name: 'Production API' },
    { host: 'staging.sign.singpass.gov.sg', port: 443, name: 'Staging Alt' },
    { host: 'sign.singpass.gov.sg', port: 443, name: 'Production Alt' }
  ];

  for (const endpoint of endpoints) {
    try {
      const connected = await testTcpConnection(endpoint.host, endpoint.port, 5000);
      results.network[`${endpoint.host}:${endpoint.port}`] = {
        success: connected,
        name: endpoint.name,
        note: connected ? 'TCP connection successful' : 'TCP connection failed'
      };
    } catch (error) {
      results.network[`${endpoint.host}:${endpoint.port}`] = {
        success: false,
        error: error.message,
        name: endpoint.name
      };
    }
  }

  // Test HTTP connectivity
  const urls = [
    'https://stg.api.sign.singpass.gov.sg/v3/signing-sessions',
    'https://api.sign.singpass.gov.sg/v3/signing-sessions',
    'https://staging.sign.singpass.gov.sg/api/v3/sign-requests',
    'https://sign.singpass.gov.sg/api/v3/sign-requests',
    'https://www.google.com' // Control
  ];

  for (const url of urls) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      
      const response = await fetch(url, {
        method: 'HEAD',
        signal: controller.signal,
        headers: {
          'User-Agent': 'Vercel-Diagnostic/1.0'
        }
      }).catch(e => ({ error: e }));
      
      clearTimeout(timeoutId);
      
      if (response.error) {
        results.endpoints[url] = {
          success: false,
          error: response.error.message,
          code: response.error.code
        };
      } else {
        results.endpoints[url] = {
          success: true,
          status: response.status,
          statusText: response.statusText,
          headers: Object.fromEntries(response.headers)
        };
      }
    } catch (error) {
      results.endpoints[url] = {
        success: false,
        error: error.message,
        code: error.code
      };
    }
  }

  // Check environment variables
  results.env_vars = {
    SINGPASS_CLIENT_ID: { 
      present: !!process.env.SINGPASS_CLIENT_ID,
      length: process.env.SINGPASS_CLIENT_ID?.length || 0
    },
    SINGPASS_KID: { 
      present: !!process.env.SINGPASS_KID,
      length: process.env.SINGPASS_KID?.length || 0
    },
    SINGPASS_PRIVATE_KEY_PEM: { 
      present: !!process.env.SINGPASS_PRIVATE_KEY_PEM,
      length: process.env.SINGPASS_PRIVATE_KEY_PEM?.length || 0
    },
    WEBHOOK_BASE_URL: { 
      present: !!process.env.WEBHOOK_BASE_URL,
      value: process.env.WEBHOOK_BASE_URL || 'not set'
    }
  };

  // Check Vercel-specific settings
  results.vercel = {
    region: process.env.VERCEL_REGION || 'unknown',
    url: process.env.VERCEL_URL || 'unknown',
    environment: process.env.VERCEL_ENV || 'unknown'
  };

  res.status(200).json(results);
};

function testTcpConnection(host, port, timeout) {
  return new Promise((resolve, reject) => {
    const socket = new (require('net').Socket)();
    
    const onError = (err) => {
      socket.destroy();
      reject(err);
    };

    socket.setTimeout(timeout);
    socket.once('error', onError);
    socket.once('timeout', () => {
      socket.destroy();
      reject(new Error('Connection timeout'));
    });

    socket.connect(port, host, () => {
      socket.end();
      resolve(true);
    });
  });
}