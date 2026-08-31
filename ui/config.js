// Overwritten at deploy time by deploy.sh with the real Cognito/API stack outputs.
// This placeholder lets the site load (and fail visibly with a clear message)
// if it is ever served before a deploy has run.
window.CRM_CONFIG = {
  region: "ap-southeast-1",
  userPoolId: "",
  userPoolClientId: "",
  apiUrl: "",
};
