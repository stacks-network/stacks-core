import { promisify } from 'util';
import { pipeline, Writable, WritableOptions, Readable } from 'stream';

const pipelineAsync = promisify(pipeline);

export class MemoryStream extends Writable {
  buffers: Buffer[] = [];
  constructor(opts?: WritableOptions) {
    super(opts);
  }
  _write(
    chunk: any,
    encoding: string,
    callback: (error?: Error | null) => void
  ): void {
    if (chunk instanceof Buffer) {
      this.buffers.push(chunk);
    } else {
      this.buffers.push(Buffer.from(chunk, encoding));
    }
    callback(null);
  }
  getData() {
    if (this.buffers.length === 1) {
      return this.buffers[0];
    }
    return Buffer.concat(this.buffers);
  }
}

export async function readStream(
  stream: Readable,
  ignoreErrors = false
): Promise<Buffer> {
  const memStream = new MemoryStream();
  if (ignoreErrors) {
    try {
      await pipelineAsync(stream, memStream);
    } catch (error) {
      console.debug(`readStream error: ${error}`);
    }
  } else {
    await pipelineAsync(stream, memStream);
  }
  return memStream.getData();
}
