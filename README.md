# WebUSB ADB / Fastboot

A browser-only implementation of the Android ADB and Fastboot protocols over
[WebUSB](https://developer.mozilla.org/en-US/docs/Web/API/WebUSB_API) — no
native app, no `adb`/`fastboot` binaries, no build step.

- `adb.js` — ADB client: USB handshake, RSA key generation, on-device
  fingerprint auth, and a `shell()` helper (plus lower-level `open()` for
  raw ADB streams).
- `fastboot.js` — Fastboot client: `getVar()`, `flash()`, `boot()`,
  `erase()`, `reboot()`.
- `index.html` — minimal demo page exercising both.

## Running the demo

WebUSB requires a secure context, so you can't just double-click
`index.html` — serve the folder locally instead:

```bash
cd webusb-adb-fastboot
python3 -m http.server 8000
```

Then open `http://localhost:8000/index.html` in **Chrome or Edge** (Firefox
and Safari don't support WebUSB).

- For the ADB panel: enable *Developer options → USB debugging* on the
  phone, plug it in, click **Connect device (ADB)**, pick it from the
  browser's device chooser, and approve the *"Allow USB debugging?"*
  prompt that appears on the phone's screen.
- For the Fastboot panel: reboot the device into bootloader/fastboot mode
  first (varies by manufacturer — often `adb reboot bootloader` or a
  hardware button combo), then click **Connect device (Fastboot)**.

## Using the libraries in your own code

```js
import { AdbDevice } from './adb.js';

const adb = await AdbDevice.requestDevice(); // opens the browser's picker
console.log(adb.deviceBanner);
console.log(await adb.shell('getprop ro.product.model'));
await adb.close();
```

```js
import { FastbootDevice } from './fastboot.js';

const fb = await FastbootDevice.requestDevice();
console.log(await fb.getVar('product'));
await fb.flash('boot', someArrayBuffer, (sent, total) => {
  console.log(`${sent}/${total}`);
});
await fb.close();
```

### Persisting the ADB key across sessions

By default `AdbDevice.requestDevice()` generates a fresh RSA key every
time, which means you'll have to tap "Allow" on the phone on every single
connection. To avoid that, generate a key once, save it, and reuse it:

```js
import { AdbKey, AdbDevice } from './adb.js';

let key;
const saved = /* load your saved JSON from wherever you store it */;
key = saved ? AdbKey.fromJSON(saved) : await AdbKey.generate();
// persist AdbKey#toJSON() somewhere of your choosing after first use

const adb = await AdbDevice.requestDevice(key);
```

(The library itself never touches `localStorage` or any other storage —
that choice, and where a persisted key should live, is left to you.)

## Known limitations / caveats

- **Not tested against real hardware by me** — this was written directly
  from the public AOSP protocol documentation and source (`protocol.txt`,
  `adb_auth_host.cpp`, `android_pubkey.c`, `fastboot`'s `protocol.txt`).
  The Fastboot half is simple enough to be quite reliable; the ADB RSA
  auth handshake has more moving parts (raw PKCS#1 padding, the AOSP
  public-key blob layout with Montgomery-multiplication helper fields) and
  is the most likely place for a subtle bug if something doesn't connect.
  If auth fails, a good first debugging step is dumping the bytes of
  `AdbKey.publicKeyBlob()` and diff-ing the struct layout against
  `android_pubkey.c`.
- **Driver conflicts on Windows** — the OS's built-in ADB/Fastboot drivers
  typically claim the USB interface before a browser gets a chance to;
  you generally need a WinUSB-compatible driver for WebUSB to see the
  device at all. Linux and macOS usually work unmodified.
- **No flow-control queuing** — `AdbStream.write()` waits for each `OKAY`
  before allowing the next write, which is correct but not maximally
  fast for large transfers; fine for shell commands, less ideal for
  bulk `sync:` file pushes.
- **ADB shell protocol v1 only** — commands run via the plain `shell:`
  service (combined stdout+stderr, no separate exit code). The newer
  `shell,v2,...:` framed protocol (separate stdout/stderr/exit-code) isn't
  implemented, though the `open()` primitive is there if you want to build
  it.
