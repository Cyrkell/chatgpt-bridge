# Cyrkell's ChatGPT bridge

ChatGPT answers on your [Cyrkell](https://cyrkell.com) relay with your own ChatGPT plan, through
OpenAI's Sign in with ChatGPT. The bridge is one file that runs on your computer, and your ChatGPT
sign-in never leaves it: the relay never sees it.

It needs Node.js 20 or later, and nothing else: it uses only what comes with Node.js, so there are no
packages to install and nothing else to trust.

## Use it

1. Get `cyrkell-chatgpt.mjs`: from this repository, or from your relay (**Setup → ChatGPT, on your
   ChatGPT plan**). They are the same file. Your relay's Setup shows its SHA-256; to compare:
   - macOS and Linux: `shasum -a 256 cyrkell-chatgpt.mjs`
   - Windows: `certutil -hashfile cyrkell-chatgpt.mjs SHA256`
2. Sign in. A browser opens, and you choose **Continue with ChatGPT**:
   `node cyrkell-chatgpt.mjs login`
3. Run it, and leave it running. The link is your relay's ChatGPT connector link, from **Setup → 1 ·
   Connect your AIs**; it is a password, so keep it to yourself:
   `node cyrkell-chatgpt.mjs run <your ChatGPT connector link>`

Also: `status` (who is signed in, and until when), `models` (the models your plan offers, for
`--model`), `logout`, and `--help`.

## What it does with your sign-in

- **Signs in** with OAuth and PKCE, with its callback on `127.0.0.1`, and registers itself as
  "Cyrkell" with a stable id for this computer (an RFC 9278 key thumbprint). There is no client
  secret and no API key. It checks the ID token's signature, issuer, audience, expiry and nonce.
- **Keeps your tokens** in files only you can read: `~/.config/cyrkell/chatgpt` (on Windows,
  `%APPDATA%\cyrkell\chatgpt`; set `CYRKELL_BRIDGE_DIR` to choose another folder). It renews them
  before they expire, and `logout` revokes them at OpenAI and deletes them here.
- **Answers** with the Responses API, with `store: false`. It answers your own messages on the relay
  and the loops you start. Your other AIs' requests are answered only with `--answer-ais`, which asks
  for your consent first.
- **Respects your plan's limits.** When the usage limit is reached, it stops asking ChatGPT for a while
  and says so on the relay, with a link to [ChatGPT's usage settings](https://chatgpt.com/settings/usage),
  where you can also cap how much Cyrkell may use.

## Where it works

It talks only to a Cyrkell relay. On the hosted service, [cyrkell.app](https://cyrkell.app), it is
turned on once OpenAI approves Sign in with ChatGPT for hosted apps; until then a hosted relay
refuses it and the bridge says so.

## License

Apache License 2.0: see [LICENSE](LICENSE). Only this bridge is open source; the rest of Cyrkell is not.
