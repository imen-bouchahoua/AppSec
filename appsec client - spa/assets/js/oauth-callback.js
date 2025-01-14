import { generateAccessTokenUrl } from "./utils.js";

const errorDiv = document.getElementById('errorDiv');

// Retrieve state and code from query parameters in redirect uri
const query = new URLSearchParams(window.location.search);

let code = query.get('code');
const state = query.get('state');

if (code) {
  code = code.replace(/\s+/g, '+');
} else {
  errorDiv.innerHTML = 'Code is not present.';
}

if (!state || state !== localStorage.getItem('state')) {
  errorDiv.innerHTML = 'Invalid state.';
}

//errorDiv.innerHTML = `Code = ${code} -- State = ${state}`;


const fetchAccessToken = async () => {
    const accessTokenUrl = generateAccessTokenUrl();
    const urlSearchParams = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      code_verifier: localStorage.getItem('code_verifier'),
    });
    localStorage.clear();
    const response = await fetch(accessTokenUrl, {
      method: 'POST',
      body: urlSearchParams,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
    const tokenResponse = await response.json();
    console.log(tokenResponse)
    return tokenResponse;
};


if (!code) {
    errorDiv.innerHTML = 'Code is not present.';
} 
else if (!state || state != localStorage.getItem('state')) {
    errorDiv.innerHTML = 'Invalid state.';
}
else {
    console.log("Fetching access token...");
    // Fetch access token from authorization server
    fetchAccessToken()
    .then(tokenResponse => {
        console.log(tokenResponse);
        const accessToken = tokenResponse.access_token;
        if (accessToken) {
          localStorage.setItem('access_token', accessToken);
          const refreshToken = tokenResponse.refresh_token;
        }
  
        const refreshToken = tokenResponse.refresh_token;
        if (refreshToken) {
          localStorage.setItem('refresh_token', refreshToken);
        }
        setTimeout(() => {
            window.location.replace(window.location.origin);
          }, 100);
      });
    
}
  