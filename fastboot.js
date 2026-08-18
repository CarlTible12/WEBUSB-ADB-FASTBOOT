// fastboot.js — WebUSB Fastboot client
//
// Implements the Android Fastboot protocol over WebUSB, based on the public
// protocol described in AOSP (system/core/fastboot/protocol.txt):
//   - Host sends an ASCII command as a single bulk OUT transfer.
//   - Device replies with one or more 4-byte-prefixed packets:
//       INFO<text>  informational, keep reading
//       OKAY<text>  success, command complete
//       FAIL<text>  failure, <text> is the reason
//       DATA<size>  device is ready to send/receive <size> bytes of raw data
//
// Usage:
//   const fb = await FastbootDevice.requestDevice();
//   console.log(await fb.getVar('product'));
//   await fb.flash('boot', someArrayBuffer);

const FASTBOOT_CLASS = 0xff;
const FASTBOOT_SUBCLASS = 0x42;
const FASTBOOT_PROTOCOL = 0x03;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export class FastbootDevice {
  constructor() {
    this.device = null;
    this.epIn = null;
    this.epOut = null;
    this.ifaceNumber = null;
  }

  // Prompts the browser's WebUSB device picker, filtered to the Fastboot
  // USB interface class/subclass/protocol.
  static async requestDevice() {
    const usb = await navigator.usb.requestDevice({
      filters: [
        {
          classCode: FASTBOOT_CLASS,
          subclassCode: FASTBOOT_SUBCLASS,
          protocolCode: FASTBOOT_PROTOCOL,
        },
      ],
    });
    const fb = new FastbootDevice();
    await fb._connect(usb);
    return fb;
  }

  async _connect(device) {
    this.device = device;
    await device.open();
    if (device.configuration === null) {
      await device.selectConfiguration(1);
    }

    let ifaceNumber = null;
    for (const iface of device.configuration.interfaces) {
      const alt = iface.alternates[0];
      if (
        alt.interfaceClass === FASTBOOT_CLASS &&
        alt.interfaceSubclass === FASTBOOT_SUBCLASS &&
        alt.interfaceProtocol === FASTBOOT_PROTOCOL
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
      throw new Error(
        'No fastboot interface found on this device. Is it in bootloader/fastboot mode?'
      );
    }
    await device.claimInterface(ifaceNumber);
    this.ifaceNumber = ifaceNumber;
  }

  async _write(data) {
    const buf = typeof data === 'string' ? textEncoder.encode(data) : data;
    await this.device.transferOut(this.epOut, buf);
  }

  async _read(len = 256) {
    const result = await this.device.transferIn(this.epIn, len);
    return new Uint8Array(result.data.buffer, result.data.byteOffset, result.data.byteLength);
  }

  // Sends a command and reads responses until OKAY/FAIL. INFO lines are
  // collected and optionally streamed via onInfo. Returns { text, infos }.
  async _runCommand(cmd, onInfo = null) {
    await this._write(cmd);
    const infos = [];
    while (true) {
      const raw = await this._read(4096);
      const text = textDecoder.decode(raw);
      const code = text.slice(0, 4);
      const payload = text.slice(4);
      if (code === 'INFO') {
        infos.push(payload);
        if (onInfo) onInfo(payload);
        continue;
      }
      if (code === 'OKAY') return { text: payload, infos };
      if (code === 'FAIL') throw new Error(`fastboot: command failed: ${payload}`);
      if (code === 'DATA') return { text: payload, infos, dataPhase: true };
      throw new Error(`fastboot: unexpected response: ${text}`);
    }
  }

  /** Reads a bootloader variable, e.g. getVar('product'), getVar('version'). */
  async getVar(name) {
    const { text } = await this._runCommand(`getvar:${name}`);
    return text;
  }

  async oemCommand(cmd, onInfo = null) {
    return this._runCommand(`oem ${cmd}`, onInfo);
  }

  /** target: '' (normal reboot), 'bootloader', or 'fastboot'. */
  async reboot(target = '') {
    return this._runCommand(target ? `reboot-${target}` : 'reboot');
  }

  async erase(partition) {
    return this._runCommand(`erase:${partition}`);
  }

  /**
   * Uploads raw bytes to the device's download buffer, ahead of a
   * flash/boot command. Chunks the transfer and reports progress.
   */
  async download(data, onProgress = null) {
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    const size = bytes.length;

    await this._write(`download:${size.toString(16).padStart(8, '0')}`);
    const respRaw = await this._read(64);
    const respText = textDecoder.decode(respRaw);
    const code = respText.slice(0, 4);
    if (code === 'FAIL') throw new Error(`fastboot: download rejected: ${respText.slice(4)}`);
    if (code !== 'DATA') throw new Error(`fastboot: unexpected response to download: ${respText}`);

    const CHUNK = 16384; // conservative bulk-transfer chunk size
    let sent = 0;
    while (sent < size) {
      const chunk = bytes.subarray(sent, Math.min(sent + CHUNK, size));
      await this.device.transferOut(this.epOut, chunk);
      sent += chunk.length;
      if (onProgress) onProgress(sent, size);
    }

    const finalRaw = await this._read(64);
    const finalText = textDecoder.decode(finalRaw);
    if (!finalText.startsWith('OKAY')) {
      throw new Error(`fastboot: download failed: ${finalText}`);
    }
  }

  /** Downloads `data` then flashes it to `partition` (e.g. 'boot', 'recovery'). */
  async flash(partition, data, onProgress = null) {
    await this.download(data, onProgress);
    return this._runCommand(`flash:${partition}`);
  }

  /** Downloads `data` (a boot image) and boots it once, without flashing. */
  async boot(data, onProgress = null) {
    await this.download(data, onProgress);
    return this._runCommand('boot');
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
