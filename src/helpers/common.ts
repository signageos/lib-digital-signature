"use strict";

import * as fs from "fs";
import { constants } from "../constants";

function needsContentDigestValidation(requestBody: string): boolean {
  return (
    requestBody !== null && requestBody !== undefined && requestBody.length > 0
  );
}

function readKey(value: string): string {
  let key: string = value;

  if (fs.existsSync(value)) {
    key = fs.readFileSync(value, {
      encoding: constants.UTF8,
    });
  }

  return key;
}

function sanitizeKey(key: string): string {
  return key.trim().replace(/[\r\n]+/g, "");
}

export { needsContentDigestValidation, readKey, sanitizeKey };
