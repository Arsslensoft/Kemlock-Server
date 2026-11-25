// Reading a QR code from a camera frame. Browsers with `BarcodeDetector` (Chromium, Safari) use
// it; the others (Firefox) draw the frame on a canvas and decode it with jsqr, loaded only when
// the scanner opens so the sign-in bundle does not carry it.

export type QrReader = (video: HTMLVideoElement) => Promise<string | undefined>;

interface Detector {
  detect: (source: HTMLVideoElement) => Promise<{ rawValue: string }[]>;
}

/** Whether this browser can scan at all: a camera, and either BarcodeDetector or a canvas. */
export function canScan(): boolean {
  return typeof navigator !== 'undefined' && typeof navigator.mediaDevices?.getUserMedia === 'function';
}

export type JsQr = (
  data: Uint8ClampedArray,
  width: number,
  height: number,
  options?: { inversionAttempts?: 'dontInvert' | 'onlyInvert' | 'attemptBoth' | 'invertFirst' },
) => { data: string } | null;

/** A reader that decodes pixels with `decode` (jsqr), drawing each frame on one canvas. */
export function pixelReader(decode: JsQr, canvas: HTMLCanvasElement = document.createElement('canvas')): QrReader {
  const context = canvas.getContext('2d', { willReadFrequently: true });
  return (video) => {
    const { videoWidth: width, videoHeight: height } = video;
    if (!context || width === 0 || height === 0) return Promise.resolve(undefined);
    canvas.width = width;
    canvas.height = height;
    context.drawImage(video, 0, 0, width, height);
    const image = context.getImageData(0, 0, width, height);
    const found = decode(image.data, width, height, { inversionAttempts: 'dontInvert' });
    return Promise.resolve(found?.data || undefined);
  };
}

export async function createQrReader(): Promise<QrReader> {
  if ('BarcodeDetector' in globalThis) {
    const Detect = (globalThis as unknown as { BarcodeDetector: new (options: object) => Detector }).BarcodeDetector;
    const detector = new Detect({ formats: ['qr_code'] });
    return async (video) => (await detector.detect(video).catch(() => []))[0]?.rawValue || undefined;
  }
  const { default: jsQR } = await import('jsqr');
  return pixelReader(jsQR);
}
