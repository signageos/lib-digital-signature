'use strict';

import * as fs from 'fs';
import { constants } from "../constants";

function needsContentDigestValidation(requestBody: string): boolean {
    return requestBody !== null &&
        requestBody !== undefined &&
        requestBody.length > 0;
}

function readKey(value: string): string {
    let key: string = value;

    if (fs.existsSync(value)) {
        key = fs.readFileSync(
            value, {
            encoding: constants.UTF8
        });
    }

    return key;
}

export { needsContentDigestValidation, readKey };
