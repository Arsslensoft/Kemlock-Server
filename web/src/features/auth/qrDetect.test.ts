import { afterEach, describe, expect, it, vi } from 'vitest';
import { createQrReader, pixelReader } from './qrDetect';

function video(width: number, height: number): HTMLVideoElement {
  return { videoWidth: width, videoHeight: height } as HTMLVideoElement;
}

function canvas(pixels: Uint8ClampedArray) {
  const context = {
    drawImage: vi.fn(),
    getImageData: vi.fn(() => ({ data: pixels })),
  };
  return { element: { getContext: () => context } as unknown as HTMLCanvasElement, context };
}

afterEach(() => vi.unstubAllGlobals());

describe('pixelReader', () => {
  it('decodes the pixels of the frame with jsqr', async () => {
    const pixels = new Uint8ClampedArray(16);
    const { element, context } = canvas(pixels);
    const decode = vi.fn(() => ({ data: 'KMK1.piece' }));
    expect(await pixelReader(decode, element)(video(2, 2))).toBe('KMK1.piece');
    expect(context.drawImage).toHaveBeenCalled();
    expect(decode).toHaveBeenCalledWith(pixels, 2, 2, { inversionAttempts: 'dontInvert' });
  });

  it('finds nothing in an empty frame or a video that has not started', async () => {
    const { element } = canvas(new Uint8ClampedArray(16));
    expect(await pixelReader(() => null, element)(video(2, 2))).toBeUndefined();
    expect(await pixelReader(() => ({ data: 'x' }), element)(video(0, 0))).toBeUndefined();
  });
});

describe('createQrReader', () => {
  it('uses BarcodeDetector where the browser has it', async () => {
    vi.stubGlobal(
      'BarcodeDetector',
      class {
        detect = () => Promise.resolve([{ rawValue: 'from-detector' }]);
      },
    );
    expect(await (await createQrReader())(video(1, 1))).toBe('from-detector');
  });
});
