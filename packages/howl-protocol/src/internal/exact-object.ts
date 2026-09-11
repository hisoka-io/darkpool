import { ProtocolParseError, type ProtocolParseErrorCode } from "../errors.js";

type ExactRecord<Keys extends readonly string[]> = {
  readonly [Key in Keys[number]]: unknown;
};

interface ExactArrayLengthPolicy {
  readonly expectedLength: number;
  readonly errorCode: ProtocolParseErrorCode;
  readonly errorMessage: string;
}

export function parseAtPath<T>(
  parser: (value: unknown) => T,
  value: unknown,
  path: string,
): T {
  try {
    return parser(value);
  } catch (error) {
    if (error instanceof ProtocolParseError) {
      const prefix = `${error.path}: `;
      const detail = error.message.startsWith(prefix)
        ? error.message.slice(prefix.length)
        : error.message;
      throw new ProtocolParseError(error.code, path, detail);
    }
    throw new ProtocolParseError(
      "INVALID_OBJECT",
      path,
      "value could not be parsed",
    );
  }
}

function inspectArray(value: object, path: string): boolean {
  try {
    return Array.isArray(value);
  } catch {
    throw new ProtocolParseError(
      "INVALID_OBJECT",
      path,
      "object type could not be inspected",
    );
  }
}

function inspectPrototype(value: object, path: string): object | null {
  try {
    return Object.getPrototypeOf(value) as object | null;
  } catch {
    throw new ProtocolParseError(
      "INVALID_OBJECT",
      path,
      "object prototype could not be inspected",
    );
  }
}

function inspectOwnKeys(value: object, path: string): readonly PropertyKey[] {
  try {
    return Reflect.ownKeys(value);
  } catch {
    throw new ProtocolParseError(
      "INVALID_OBJECT",
      path,
      "object properties could not be inspected",
    );
  }
}

function inspectDescriptor(
  value: object,
  key: string,
  path: string,
): PropertyDescriptor | undefined {
  try {
    return Object.getOwnPropertyDescriptor(value, key);
  } catch {
    throw new ProtocolParseError(
      "INVALID_OBJECT",
      path,
      "object properties could not be inspected",
    );
  }
}

function readEnumerableDataProperty(
  value: object,
  key: string,
  objectPath: string,
): unknown {
  const propertyPath = `${objectPath}.${key}`;
  const descriptor = inspectDescriptor(value, key, objectPath);
  if (descriptor === undefined) {
    throw new ProtocolParseError(
      "INVALID_OBJECT",
      propertyPath,
      "object is missing a required own property",
    );
  }
  if (!("value" in descriptor) || !descriptor.enumerable) {
    throw new ProtocolParseError(
      "INVALID_OBJECT",
      propertyPath,
      "property must be an enumerable own data property",
    );
  }
  return descriptor.value;
}

export function readExactObject<const Keys extends readonly string[]>(
  value: unknown,
  expectedKeys: Keys,
  path: string,
): ExactRecord<Keys> {
  if (
    typeof value !== "object" ||
    value === null ||
    inspectArray(value, path)
  ) {
    throw new ProtocolParseError(
      "INVALID_OBJECT",
      path,
      "expected a plain object",
    );
  }

  const prototype = inspectPrototype(value, path);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new ProtocolParseError(
      "INVALID_OBJECT",
      path,
      "object must have Object.prototype or a null prototype",
    );
  }

  const ownKeys = inspectOwnKeys(value, path);
  const expected = new Set<string>(expectedKeys);
  for (const key of ownKeys) {
    if (typeof key !== "string" || !expected.has(key)) {
      throw new ProtocolParseError(
        "UNEXPECTED_PROPERTY",
        typeof key === "string" ? `${path}.${key}` : path,
        "object contains an unexpected property",
      );
    }
  }

  const copy = Object.create(null) as Record<string, unknown>;
  for (const key of expectedKeys) {
    copy[key] = readEnumerableDataProperty(value, key, path);
  }
  return copy as ExactRecord<Keys>;
}

export function readExactArray(
  value: unknown,
  path: string,
  lengthPolicy: ExactArrayLengthPolicy,
): readonly unknown[] {
  if (
    typeof value !== "object" ||
    value === null ||
    !inspectArray(value, path)
  ) {
    throw new ProtocolParseError("INVALID_OBJECT", path, "expected an array");
  }

  if (inspectPrototype(value, path) !== Array.prototype) {
    throw new ProtocolParseError(
      "INVALID_OBJECT",
      path,
      "array must have Array.prototype",
    );
  }

  const lengthDescriptor = inspectDescriptor(value, "length", path);
  if (
    lengthDescriptor === undefined ||
    !("value" in lengthDescriptor) ||
    typeof lengthDescriptor.value !== "number" ||
    !Number.isInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0
  ) {
    throw new ProtocolParseError(
      "INVALID_OBJECT",
      path,
      "array length must be an own integer data property",
    );
  }

  const length = lengthDescriptor.value;
  if (length !== lengthPolicy.expectedLength) {
    throw new ProtocolParseError(
      lengthPolicy.errorCode,
      path,
      lengthPolicy.errorMessage,
    );
  }

  const ownKeys = inspectOwnKeys(value, path);
  let entryCount = 0;
  let hasLength = false;
  for (const key of ownKeys) {
    if (key === "length") {
      hasLength = true;
      continue;
    }
    const index = typeof key === "string" ? Number(key) : -1;
    if (
      typeof key !== "string" ||
      !Number.isInteger(index) ||
      index < 0 ||
      index >= length ||
      String(index) !== key
    ) {
      throw new ProtocolParseError(
        "UNEXPECTED_PROPERTY",
        typeof key === "string" ? `${path}.${key}` : path,
        "array contains an unexpected property",
      );
    }
    entryCount += 1;
  }
  if (!hasLength || entryCount !== length) {
    throw new ProtocolParseError(
      "INVALID_OBJECT",
      path,
      "array must contain one own data property per entry",
    );
  }

  const copy: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const key = String(index);
    const descriptor = inspectDescriptor(value, key, path);
    const itemPath = `${path}[${index}]`;
    if (descriptor === undefined) {
      throw new ProtocolParseError(
        "INVALID_OBJECT",
        itemPath,
        "array is missing a required own entry",
      );
    }
    if (!("value" in descriptor) || !descriptor.enumerable) {
      throw new ProtocolParseError(
        "INVALID_OBJECT",
        itemPath,
        "array entry must be an enumerable own data property",
      );
    }
    copy.push(descriptor.value);
  }
  return copy;
}
