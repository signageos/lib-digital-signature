'use strict';
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sanitizeKey = exports.readKey = exports.needsContentDigestValidation = void 0;
const fs = __importStar(require("fs"));
const constants_1 = require("../constants");
function needsContentDigestValidation(requestBody) {
    return requestBody !== null &&
        requestBody !== undefined &&
        requestBody.length > 0;
}
exports.needsContentDigestValidation = needsContentDigestValidation;
function readKey(value) {
    let key = value;
    if (fs.existsSync(value)) {
        key = fs.readFileSync(value, {
            encoding: constants_1.constants.UTF8
        });
    }
    return key;
}
exports.readKey = readKey;
function sanitizeKey(key) {
    return key.trim().replace(/[\r\n]+/g, '');
}
exports.sanitizeKey = sanitizeKey;
