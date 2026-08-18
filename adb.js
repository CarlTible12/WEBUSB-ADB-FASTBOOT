// adb.js — WebUSB ADB client
//
// Implements enough of the Android Debug Bridge (ADB) protocol to open a
// USB connection, perform RSA-key authentication, and run shell commands,
// based on the protocol documented in AOSP (system/core/adb/protocol.txt,
// adb/adb_auth_host.cpp, libcrypto_utils/android_pubkey.c).
//
// This is a from-scratch, browser-only reimplementation (no dependency on
// Node's crypto or any external crypto library) — RSA key generation uses
// the Web Crypto API, and the ADB-specific "raw" PKCS#1 v1.5 signing and
// the AOSP public-key blob format are implemented by hand with BigInt.
//
// Usage:
//   const adb = await AdbDevice.requestDevice();      // prompts device picker
//   console.log(await adb.shell('getprop ro.product.model'));
//
// The very first time you connect to a given phone, adbd will show an
// on-device "Allow USB debugging?" fingerprint prompt — the handshake
// below waits for that automatically.

const ADB_CLASS = 0xff;
const ADB_SUBCLASS = 0x42;
const ADB_PROTOCOL = 0x01;

const A_CNXN = 0x4e584e43;
const A_OPEN = 0x4e45504f;
const A_OKAY = 0x59414b4f;
const A_CLSE = 0x45534c43;
const A_WRTE = 0x45545257;
const A_AUTH = 0x48545541;

const A_VERSION = 0x01000000;
const MAX_PAYLOAD = 1024 * 1024; // 1MB, advertised as our max receive size

const AUTH_TOKEN = 1;
const AUTH_SIGNATURE = 2;
const AUTH_RSAPUBLICKEY = 3;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

// ---------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------

function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

// ---------------------------------------------------------------------
// BigInt RSA helpers, for ADB's un-hashed PKCS#1 v1.5 signing scheme and
// its custom public-key blob format
// ---------------------------------------------------------------------

function modPow(base, exp, mod) {
  base %= mod;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function modInverse(a, m) {
  let [oldR, r] = [a, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return ((oldS % m) + m) % m;
}

function bytesToBigInt(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

function bigIntToBytesBE(num, len) {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(num & 0xffn);
    num >>= 8n;
  }
  return out;
}

function bigIntToBytesLE(num, len) {
  return bigIntToBytesBE(num, len).reverse();
}

function b64urlToBigInt(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytesToBigInt(bytes);
}

// DER prefix for a SHA-1 DigestInfo (RFC 3447 §9.2, Note 1). ADB's auth
// token is a raw 20-byte value that gets wrapped with this prefix and
// PKCS#1 v1.5-padded *without* being hashed again — this mirrors what
// OpenSSL's RSA_sign(NID_sha1, token, 20, ...) does under the hood, which
// is what the real adb client and adbd both use.
const SHA1_DIGEST_INFO_PREFIX = new Uint8Array([
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
]);

export class AdbKey {
  constructor(n, e, d, keySizeBytes) {
    this.n = n;
    this.e = e;
    this.d = d;
    this.keySizeBytes = keySizeBytes;
  }

  /** Generates a fresh 2048-bit RSA key pair using the Web Crypto API. */
  static async generate() {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: 'SHA-1',
      },
      true,
      ['sign', 'verify']
    );
    const jwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    const n = b64urlToBigInt(jwk.n);
    const e = b64urlToBigInt(jwk.e);
    const d = b64urlToBigInt(jwk.d);
    return new AdbKey(n, e, d, 256); // 2048 bits / 8 = 256 bytes
  }

  /** Serializes to a plain object so the caller can persist/restore the key. */
  toJSON() {
    return { n: this.n.toString(16), e: this.e.toString(16), d: this.d.toString(16), keySizeBytes: this.keySizeBytes };
  }

  static fromJSON(obj) {
    return new AdbKey(BigInt('0x' + obj.n), BigInt('0x' + obj.e), BigInt('0x' + obj.d), obj.keySizeBytes);
  }

  /** Raw PKCS#1 v1.5 signature over the pre-computed 20-byte auth token. */
  signToken(token) {
    const digestInfo = concatBytes(SHA1_DIGEST_INFO_PREFIX, token);
    const emLen = this.keySizeBytes;
    const psLen = emLen - digestInfo.length - 3;
    if (psLen < 8) throw new Error('RSA key too small for PKCS#1 padding');
    const em = new Uint8Array(emLen);
    em[0] = 0x00;
    em[1] = 0x01;
    for (let i = 0; i < psLen; i++) em[2 + i] = 0xff;
    em[2 + psLen] = 0x00;
    em.set(digestInfo, 3 + psLen);
    const m = bytesToBigInt(em);
    const s = modPow(m, this.d, this.n);
    return bigIntToBytesBE(s, emLen);
  }

  /**
   * Builds the ADB "public key" blob: AOSP's RSAPublicKey struct
   * (len, n0inv, modulus, rr, exponent), base64-encoded with a trailing
   * name comment — this is what's sent in an AUTH RSAPUBLICKEY packet and
   * what shows up in the on-device fingerprint prompt / adb_keys file.
   */
  publicKeyBlob(comment = 'webusb-adb') {
    const words = this.keySizeBytes / 4; // 64 for a 2048-bit key
    const TWO32 = 1n << 32n;
    const n0 = this.n & 0xffffffffn;
    const n0inv = (TWO32 - modInverse(n0, TWO32)) % TWO32;
    const rr = modPow(2n, BigInt(this.keySizeBytes * 8 * 2), this.n); // R^2 mod n, R = 2^(8*keySizeBytes)

    const buf = new Uint8Array(4 + 4 + this.keySizeBytes + this.keySizeBytes + 4);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, words, true);
    dv.setUint32(4, Number(n0inv), true);
    buf.set(bigIntToBytesLE(this.n, this.keySizeBytes), 8);
    buf.set(bigIntToBytesLE(rr, this.keySizeBytes), 8 + this.keySizeBytes);
    dv.setUint32(8 + this.keySizeBytes * 2, Number(this.e), true);

    let bin = '';
    for (const b of buf) bin += String.fromCharCode(b);
    return `${btoa(bin)} ${comment}\0`;
  }
}

// ---------------------------------------------------------------------
// ADB packet (24-byte header + optional payload)
// ---------------------------------------------------------------------

class AdbPacket {
  constructor(command, arg0, arg1, data = new Uint8Array(0)) {
    this.command = command;
    this.arg0 = arg0;
    this.arg1 = arg1;
    this.data = data;
  }

  toBytes() {
    const header = new Uint8Array(24);
    const dv = new DataView(header.buffer);
    dv.setUint32(0, this.command, true);
    dv.setUint32(4, this.arg0, true);
    dv.setUint32(8, this.arg1, true);
    dv.setUint32(12, this.data.length, true);
    dv.setUint32(16, crc32(this.data), true);
    dv.setUint32(20, (this.command ^ 0xffffffff) >>> 0, true);
    return concatBytes(header, this.data);
  }

  static parseHeader(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return {
      command: dv.getUint32(0, true),
      arg0: dv.getUint32(4, true),
      arg1: dv.getUint32(8, true),
      dataLength: dv.getUint32(12, true),
    };
  }
}

// ---------------------------------------------------------------------
// AdbStream — one OPEN'd service (e.g. a shell command)
// ---------------------------------------------------------------------

class AdbStream {
  constructor(adb, localId) {
    this.adb = adb;
    this.localId = localId;
    this.remoteId = 0;
    this.closed = false;
    this._incoming = [];
    this._waiters = [];
  }

  _push(chunkOrNull) {
    if (this._waiters.length) this._waiters.shift()(chunkOrNull);
    else this._incoming.push(chunkOrNull);
  }

  /** Reads the next chunk of output, or null once the stream is closed. */
  async read() {
    if (this._incoming.length) return this._incoming.shift();
    if (this.closed) return null;
    return new Promise((resolve) => this._waiters.push(resolve));
  }

  /** Reads until the stream closes and returns everything received. */
  async readAll() {
    const chunks = [];
    for (let chunk = await this.read(); chunk !== null; chunk = await this.read()) {
      chunks.push(chunk);
    }
    return concatBytes(...chunks);
  }

  async write(data) {
    const bytes = typeof data === 'string' ? textEncoder.encode(data) : data;
    await this.adb._send(new AdbPacket(A_WRTE, this.localId, this.remoteId, bytes));
    await this.adb._waitForOkay(this.localId);
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    await this.adb._send(new AdbPacket(A_CLSE, this.localId, this.remoteId));
  }
}

// ---------------------------------------------------------------------
// AdbDevice
// ---------------------------------------------------------------------

export class AdbDevice {
  constructor(key) {
    this.device = null;
    this.epIn = null;
    this.epOut = null;
    this.ifaceNumber = null;
    this.key = key;
    this.connected = false;
    this.deviceBanner = '';
    this._nextLocalId = 1;
    this._streams = new Map(); // our localId -> AdbStream
    this._okayWaiters = new Map(); // our localId -> resolve(remoteId)
  }

  /**
   * Prompts the browser's WebUSB device picker (filtered to the ADB
   * interface) and performs the full connect + auth handshake.
   * Pass a previously-saved AdbKey (see AdbKey#toJSON/fromJSON) to avoid
   * re-approving the fingerprint prompt on every connection.
   */
  static async requestDevice(key) {
    const usb = await navigator.usb.requestDevice({
      filters: [{ classCode: ADB_CLASS, subclassCode: ADB_SUBCLASS, protocolCode: ADB_PROTOCOL }],
    });
    const adb = new AdbDevice(key || (await AdbKey.generate()));
    await adb._connect(usb);
    return adb;
  }

  async _connect(device) {
    this.device = device;
    await device.open();
    if (device.configuration === null) await device.selectConfiguration(1);

    let ifaceNumber = null;
    for (const iface of device.configuration.interfaces) {
      const alt = iface.alternates[0];
      if (
        alt.interfaceClass === ADB_CLASS &&
        alt.interfaceSubclass === ADB_SUBCLASS &&
        alt.interfaceProtocol === ADB_PROTOCOL
      ) {
        ifaceNumber = iface.interfaceNumber;
        for (const ep of alt.endpoints) {
          if (ep.direction === 'in') this.epIn = ep.endpointNumber;
          if (ep.direction === 'out') this.epOut = ep.endpointNumber;
        }
        break;
      }
    }
    if (ifaceNumber === null) {
      throw new Error('No ADB interface found on this device. Is USB debugging enabled?');
    }
    await device.claimInterface(ifaceNumber);
    this.ifaceNumber = ifaceNumber;

    // Handshake first, using direct reads — only after CNXN succeeds do we
    // hand off to the background dispatch loop, so the two never race for
    // the same USB IN transfers.
    await this._handshake();
    this._readLoop().catch((e) => console.error('ADB read loop stopped:', e));
  }

  async _send(packet) {
    await this.device.transferOut(this.epOut, packet.toBytes());
  }

  async _readExactly(len) {
    const chunks = [];
    let got = 0;
    while (got < len) {
      const result = await this.device.transferIn(this.epIn, len - got);
      const chunk = new Uint8Array(result.data.buffer, result.data.byteOffset, result.data.byteLength);
      chunks.push(chunk);
      got += chunk.length;
    }
    return concatBytes(...chunks);
  }

  async _readPacket() {
    const headerBytes = await this._readExactly(24);
    const header = AdbPacket.parseHeader(headerBytes);
    const data = header.dataLength > 0 ? await this._readExactly(header.dataLength) : new Uint8Array(0);
    return { header, data };
  }

  async _handshake() {
    const systemId = 'host::features=cmd,shell_v2\0';
    await this._send(new AdbPacket(A_CNXN, A_VERSION, MAX_PAYLOAD, textEncoder.encode(systemId)));

    let triedSignature = false;
    while (true) {
      const { header, data } = await this._readPacket();
      if (header.command === A_CNXN) {
        this.connected = true;
        this.deviceBanner = textDecoder.decode(data);
        return;
      }
      if (header.command !== A_AUTH || header.arg0 !== AUTH_TOKEN) {
        throw new Error(`ADB: unexpected packet during handshake (0x${header.command.toString(16)})`);
      }
      if (!triedSignature) {
        triedSignature = true;
        const signature = this.key.signToken(data);
        await this._send(new AdbPacket(A_AUTH, AUTH_SIGNATURE, 0, signature));
      } else {
        // Our key wasn't already trusted. Send the public key itself — the
        // user now needs to approve the "Allow USB debugging?" prompt on
        // the device. We just keep waiting for CNXN after this.
        const pubKey = textEncoder.encode(this.key.publicKeyBlob());
        await this._send(new AdbPacket(A_AUTH, AUTH_RSAPUBLICKEY, 0, pubKey));
      }
    }
  }

  // Background loop dispatching WRTE/OKAY/CLSE to open streams once connected.
  async _readLoop() {
    while (true) {
      const { header, data } = await this._readPacket();
      switch (header.command) {
        case A_OKAY: {
          const resolve = this._okayWaiters.get(header.arg1);
          if (resolve) {
            this._okayWaiters.delete(header.arg1);
            resolve(header.arg0); // arg0 = sender's (remote) local-id
          }
          break;
        }
        case A_WRTE: {
          const stream = this._streams.get(header.arg1);
          if (stream) {
            stream.remoteId = header.arg0;
            stream._push(data);
            await this._send(new AdbPacket(A_OKAY, header.arg1, header.arg0));
          }
          break;
        }
        case A_CLSE: {
          const stream = this._streams.get(header.arg1);
          if (stream) {
            stream.closed = true;
            stream._push(null);
            this._streams.delete(header.arg1);
          }
          break;
        }
        default:
          break; // ignore stray CNXN/AUTH repeats
      }
    }
  }

  _waitForOkay(localId) {
    return new Promise((resolve) => this._okayWaiters.set(localId, resolve));
  }

  /**
   * Opens a new stream for an ADB service string, e.g. "shell:ls -la",
   * "shell,v2,raw:bash -l", or "sync:" for the file transfer protocol.
   */
  async open(service) {
    const localId = this._nextLocalId++;
    const stream = new AdbStream(this, localId);
    this._streams.set(localId, stream);
    await this._send(new AdbPacket(A_OPEN, localId, 0, textEncoder.encode(service + '\0')));
    stream.remoteId = await this._waitForOkay(localId);
    return stream;
  }

  /** Runs a one-shot shell command and returns its combined stdout/stderr as text. */
  async shell(command) {
    const stream = await this.open(`shell:${command}`);
    const out = await stream.readAll();
    return textDecoder.decode(out);
  }

  async close() {
    if (!this.device) return;
    try {
      await this.device.releaseInterface(this.ifaceNumber);
    } catch (e) {
      /* ignore */
    }
    try {
      await this.device.close();
    } catch (e) {
      /* ignore */
    }
  }
}
