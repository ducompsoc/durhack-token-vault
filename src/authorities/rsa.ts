import type { KeyObject } from "node:crypto"
import { readFile, writeFile } from "node:fs/promises"
import {
  type JWTVerifyOptions,
  type JWTVerifyResult,
  type SignJWT,
  generateKeyPair,
  importPKCS8,
  importSPKI,
  jwtVerify,
} from "jose"

import { TokenAuthority, type TokenAuthorityOptions } from "@/authorities/base"

export type RSATokenAuthorityOptions = TokenAuthorityOptions & {
  publicKey: KeyObject
  privateKey: KeyObject
}

export class RSATokenAuthority extends TokenAuthority {
  declare publicKey: KeyObject
  declare privateKey: KeyObject

  constructor({ publicKey, privateKey, ...rest }: RSATokenAuthorityOptions) {
    super(rest)
    this.publicKey = publicKey
    this.privateKey = privateKey
  }

  async signToken(token: SignJWT): Promise<string> {
    return await token.setProtectedHeader({ alg: "RS256" }).sign(this.privateKey)
  }

  async verifyToken(payload: string | Uint8Array, options: JWTVerifyOptions): Promise<JWTVerifyResult> {
    return await jwtVerify(payload, this.publicKey, options)
  }

  static async fromKeyStrings({
    publicKey: publicKeyString,
    privateKey: privateKeyString,
    ...options
  }: TokenAuthorityOptions & { publicKey: string; privateKey: string }) {
    const [publicKey, privateKey] = await Promise.all([
      importSPKI<KeyObject>(publicKeyString, "RS256"),
      importPKCS8<KeyObject>(privateKeyString, "RS256"),
    ])
    return new RSATokenAuthority({ publicKey, privateKey, ...options })
  }

  static async fromNewKeyPair({
    publicKeyFilePath,
    privateKeyFilePath,
    ...options
  }: TokenAuthorityOptions & { publicKeyFilePath: string; privateKeyFilePath: string }) {
    console.debug("Generating key pair...")
    const { publicKey, privateKey } = await generateKeyPair<KeyObject>("RS256")
    console.debug("Generated key pair.")
    console.debug("Writing key pair to filesystem...")

    async function writePublicKey() {
      await writeFile(
        publicKeyFilePath,
        await publicKey.export({
          type: "spki",
          format: "pem",
        }),
      )
      console.debug(`Written public key to ${publicKeyFilePath}`)
    }

    async function writePrivateKey() {
      await writeFile(
        privateKeyFilePath,
        await privateKey.export({
          type: "pkcs8",
          format: "pem",
        }),
      )
      console.debug(`Written private key to ${privateKeyFilePath}`)
    }

    await Promise.all([writePublicKey(), writePrivateKey()])

    console.debug("Written key pair to filesystem.")
    return new RSATokenAuthority({ publicKey, privateKey, ...options })
  }

  static async fromFilePaths({
    publicKeyFilePath,
    privateKeyFilePath,
    ...options
  }: TokenAuthorityOptions & {
    publicKeyFilePath: string
    privateKeyFilePath: string
  }): Promise<RSATokenAuthority> {
    let publicKey: string
    let privateKey: string
    try {
      ;[publicKey, privateKey] = await Promise.all([
        readFile(publicKeyFilePath, { encoding: "utf-8" }),
        readFile(privateKeyFilePath, { encoding: "utf-8" }),
      ])
    } catch (error) {
      if ((error as { code: unknown }).code === "ENOENT") {
        console.error("RSA key pair not found, generating new key pair.")
        return await RSATokenAuthority.fromNewKeyPair({ publicKeyFilePath, privateKeyFilePath, ...options })
      }
      throw error
    }

    return await RSATokenAuthority.fromKeyStrings({ publicKey, privateKey, ...options })
  }
}
