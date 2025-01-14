import { AUTHORIZE_ENDPOINT, CLIENT_ID, REDIRECT_URI_SUFFIX , TOKEN_ENDPOINT } from "./constants.js";

const DEFAULT_LAKE = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const SCOPES = 'read write';

export const generateAuthorizationUrl = async () => {
  const redirectUri = window.location.origin + REDIRECT_URI_SUFFIX ;
  const state = generateRandomString(16);
  localStorage.clear();
  localStorage.setItem('state', state);

  // Proof Kye for Code Exchange (PKCE)
  const codeVerifier = generateCodeVerifier();
  let codeChallenge = codeVerifier;
  let codeChallengeMethod = 'S256';
  localStorage.setItem('code_verifier', codeVerifier);

  try {
      codeChallenge = await computeCodeChallenge(codeVerifier);
      codeChallengeMethod = 'S256';
  } catch {}

  return `${AUTHORIZE_ENDPOINT}?client_id=${CLIENT_ID}&response_type=code` +
    `&state=${state}&redirect_uri=${redirectUri}&scope=${SCOPES}` +
    `&code_challenge=${codeChallenge}` +
    `&code_challenge_method=${codeChallengeMethod}`;
};

export const generateAccessTokenUrl = () => {
  return TOKEN_ENDPOINT;
}

const computeCodeChallenge = async (codeVerifier = "abcd") => {
  const data = new TextEncoder().encode(codeVerifier);
  const hash = await window.crypto.subtle.digest('SHA-256', data);
  const hashArray = new Uint8Array(hash);
  const hashString = String.fromCharCode.apply(null, hashArray);
  return base64UrlEncode(hashString, true);
};

const base64UrlEncode = (data, removePadding = false) => {
  let result = btoa(data)
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  if (removePadding) {
    result = result.replace(/=+$/, '')
  }
  return result;
};

const generateCodeVerifier = () => generateSecureRandomString(64, DEFAULT_LAKE + "-._~");

const generateSecureRandomString = (len = 64, lake = DEFAULT) => {
  const indices = new Uint8Array(len);
  crypto.getRandomValues(indices);
  let result = "";
  for (let i = 0; i < len; i++) {
    const index = indices[i] % lake.length;
    result += lake[index];
  }

  return result;
};

const generateRandomString = (len = 10, lake = DEFAULT_LAKE) => {
  let result = "";
  for (let i = 0; i < len; i++) {
    const index = Math.floor(Math.random() * lake.length);
    result += lake[index];
  }
  return result;
};