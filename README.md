# AITMWorker
This repository contains a proof of concept that allows you to perform AITM phishing attacks on Microsoft tenants by using a Cloudflare Worker. We are protecting hundreds of Microsoft tenants against phishing attacks using the approach described [here](https://zolder.io/using-honeytokens-to-detect-aitm-phishing-attacks-on-your-microsoft-365-tenant/).

We detected previously unknown phishing attacks on our clients abusing Cloudflare Workers. We tried to reproduce the attack by building our own Cloudflare Worker, to demonstrate how these attackers are abusing Cloudflare. This repository contains the code.

# How to use
1) Create a Cloudflare Worker in your Cloudflare account
2) Modify the `webhook` variable to your own Teams channel Webhook
3) Upload the `worker.js` code
4) Visit your workers URL and login with a victim account
5) Check your Teams channel. Credentials & cookies are posted in the channel

# Disclaimer

This code is for demonstration purposes only. We are not responsible for any misuse. Our goal is to make defenders aware of these attacks and to improve their mitigations.
