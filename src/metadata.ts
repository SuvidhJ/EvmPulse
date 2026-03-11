// ============================================================
// CBOR metadata parser — extracts Solidity compiler metadata
// appended after the executable bytecode.
// Format: [...code...][CBOR map][2-byte length]
// ============================================================

import { CborMetadata } from './types';
import { bytesToHex } from './utils';

interface CborValue {
  type: 'uint' | 'bytes' | 'text' | 'map';
  value: number | Uint8Array | string | Array<[CborValue, CborValue]>;
}

/**
 * Minimal CBOR decoder — only handles the types used in Solidity metadata
 */
function decodeCbor(
  data: Uint8Array,
  offset: number
): { value: CborValue; bytesRead: number } {
  if (offset >= data.length) {
    throw new Error('CBOR: unexpected end of data');
  }

  const initial = data[offset];
  // CBOR encodes the type in the top 3 bits and length info in the bottom 5 bits
  const majorType = initial >> 5;       // 0=uint, 2=bytes, 3=text, 5=map
  const additionalInfo = initial & 0x1f; // length or length-of-length indicator

  let argumentValue: number;
  let headerSize = 1;

  // CBOR length encoding: values < 24 are stored directly in the 5-bit field,
  // 24 = next 1 byte, 25 = next 2 bytes, 26 = next 4 bytes
  if (additionalInfo < 24) {
    argumentValue = additionalInfo;
  } else if (additionalInfo === 24) {
    argumentValue = data[offset + 1];
    headerSize = 2;
  } else if (additionalInfo === 25) {
    argumentValue = (data[offset + 1] << 8) | data[offset + 2];
    headerSize = 3;
  } else if (additionalInfo === 26) {
    argumentValue =
      (data[offset + 1] << 24) |
      (data[offset + 2] << 16) |
      (data[offset + 3] << 8) |
      data[offset + 4];
    headerSize = 5;
  } else {
    throw new Error(`CBOR: unsupported additional info ${additionalInfo}`);
  }

  switch (majorType) {
    case 0: // unsigned integer
      return {
        value: { type: 'uint', value: argumentValue },
        bytesRead: headerSize,
      };

    case 2: // byte string
      const bytes = data.slice(offset + headerSize, offset + headerSize + argumentValue);
      return {
        value: { type: 'bytes', value: bytes },
        bytesRead: headerSize + argumentValue,
      };

    case 3: // text string
      const textBytes = data.slice(offset + headerSize, offset + headerSize + argumentValue);
      const text = new TextDecoder().decode(textBytes);
      return {
        value: { type: 'text', value: text },
        bytesRead: headerSize + argumentValue,
      };

    case 5: // map
      const entries: Array<[CborValue, CborValue]> = [];
      let pos = offset + headerSize;
      for (let i = 0; i < argumentValue; i++) {
        const key = decodeCbor(data, pos);
        pos += key.bytesRead;
        const val = decodeCbor(data, pos);
        pos += val.bytesRead;
        entries.push([key.value, val.value]);
      }
      return {
        value: { type: 'map', value: entries },
        bytesRead: pos - offset,
      };

    default:
      throw new Error(`CBOR: unsupported major type ${majorType}`);
  }
}

/**
 * Separate compiler metadata from executable bytecode.
 * Returns the executable code region and parsed metadata.
 */
export function separateMetadata(bytecode: Uint8Array): {
  executableCode: Uint8Array;
  metadata: CborMetadata;
} {
  const empty: CborMetadata = {
    detected: false,
    cborLength: 0,
    solcVersion: null,
    ipfsHash: null,
    bzzr0Hash: null,
    bzzr1Hash: null,
    rawHex: '',
  };

  if (bytecode.length < 4) {
    return { executableCode: bytecode, metadata: empty };
  }

  // Solidity appends: [code][CBOR metadata][2-byte big-endian length of CBOR]
  // So the last 2 bytes tell us how long the CBOR section is
  const len = bytecode.length;
  const cborLen = (bytecode[len - 2] << 8) | bytecode[len - 1];

  // Sanity checks
  if (cborLen <= 0 || cborLen >= len - 2 || cborLen > 512) {
    return { executableCode: bytecode, metadata: empty };
  }

  const cborStart = len - 2 - cborLen;
  const cborData = bytecode.slice(cborStart, len - 2);

  // Validate: first byte should indicate a CBOR map (major type 5)
  if ((cborData[0] >> 5) !== 5) {
    return { executableCode: bytecode, metadata: empty };
  }

  const result: CborMetadata = {
    detected: true,
    cborLength: cborLen,
    solcVersion: null,
    ipfsHash: null,
    bzzr0Hash: null,
    bzzr1Hash: null,
    rawHex: bytesToHex(cborData),
  };

  try {
    const decoded = decodeCbor(cborData, 0);
    if (decoded.value.type === 'map') {
      const entries = decoded.value.value as Array<[CborValue, CborValue]>;
      for (const [key, val] of entries) {
        const keyStr = key.type === 'text' ? (key.value as string) : null;
        if (!keyStr) continue;

        if (keyStr === 'solc' && val.type === 'bytes') {
          const solcBytes = val.value as Uint8Array;
          if (solcBytes.length === 3) {
            result.solcVersion = `${solcBytes[0]}.${solcBytes[1]}.${solcBytes[2]}`;
          }
        } else if (keyStr === 'ipfs' && val.type === 'bytes') {
          result.ipfsHash = bytesToHex(val.value as Uint8Array);
        } else if (keyStr === 'bzzr0' && val.type === 'bytes') {
          result.bzzr0Hash = bytesToHex(val.value as Uint8Array);
        } else if (keyStr === 'bzzr1' && val.type === 'bytes') {
          result.bzzr1Hash = bytesToHex(val.value as Uint8Array);
        }
      }
    }
  } catch {
    // CBOR parsing failed — still separate the code, but metadata is partial
  }

  const executableCode = bytecode.slice(0, cborStart);
  return { executableCode, metadata: result };
}