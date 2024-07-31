import ModuleError from "module-error"

import type { TokenAuthorityOptions } from "@/authorities/base"
import { HSATokenAuthority } from "@/authorities/hsa"
import { RSATokenAuthority } from "@/authorities/rsa"
import type { TokenType } from "@/token-type"
import {EdDSATokenAuthority} from "@/authorities/eddsa";

export type EdDSATokenAuthorityConfig = TokenAuthorityOptions & {
  algorithm: "eddsa"
  for: TokenType
  publicKeyFilePath: string
  privateKeyFilePath: string
}

export type RSATokenAuthorityConfig = TokenAuthorityOptions & {
  algorithm: "rsa"
  for: TokenType
  publicKeyFilePath: string
  privateKeyFilePath: string
}


export type HSATokenAuthorityConfig = TokenAuthorityOptions & {
  algorithm: "hsa"
  for: TokenType
  secret: string
}

export type FilePathResolver = (filePath: string) => string;

export type TokenAuthorityConfig = { filePathResolver?: FilePathResolver } & (never 
  | EdDSATokenAuthorityConfig
  | RSATokenAuthorityConfig 
  | HSATokenAuthorityConfig
)

export async function getAuthority({ filePathResolver, ...options}: TokenAuthorityConfig) {
  if (options.algorithm === "eddsa") {
    console.debug(`Instantiating EdDSA authority for ${options.for}...`)
    if (filePathResolver != null) {
      options.publicKeyFilePath = filePathResolver(options.publicKeyFilePath)
      options.privateKeyFilePath = filePathResolver(options.privateKeyFilePath)
    }
    return {
      for: options.for,
      authority: await EdDSATokenAuthority.fromFilePaths(options),
    }
  }
  
  if (options.algorithm === "rsa") {
    console.debug(`Instantiating RSA authority for ${options.for}...`)
    if (filePathResolver != null) {
      options.publicKeyFilePath = filePathResolver(options.publicKeyFilePath)
      options.privateKeyFilePath = filePathResolver(options.privateKeyFilePath)
    }
    return {
      for: options.for,
      authority: await RSATokenAuthority.fromFilePaths(options),
    }
  }

  if (options.algorithm === "hsa") {
    console.debug(`Instantiating HSA authority for ${options.for}...`)
    return {
      for: options.for,
      authority: new HSATokenAuthority(options),
    }
  }

  throw new ModuleError("Invalid TokenVault authority configuration.", { code: "ERR_INVALID_TOKEN_AUTHORITY_CONFIG" })
}
