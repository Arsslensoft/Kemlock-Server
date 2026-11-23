// Reads a chosen file's bytes. `Blob.arrayBuffer` is used where the engine has it; `FileReader` is
// the fallback (older engines, and test environments that predate it).
export function readBytes(file: Blob): Promise<Uint8Array> {
  if (typeof file.arrayBuffer === 'function') {
    return file.arrayBuffer().then((buffer) => new Uint8Array(buffer));
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
    reader.onerror = () => reject(reader.error ?? new Error('could not read the file'));
    reader.readAsArrayBuffer(file);
  });
}
