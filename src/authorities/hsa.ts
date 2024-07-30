import { type JWTVerifyOptions, type JWTVerifyResult, type SignJWT, jwtVerify } from "jose"

import { TokenAuthority, type TokenAuthorityOptions } from "@/authorities/base"

export type HSATokenAuthorityOptions = TokenAuthorityOptions & {
  secret: string
}

export class HSATokenAuthority extends TokenAuthority {
  declare secret: Uint8Array

  constructor({ secret, ...rest }: HSATokenAuthorityOptions) {
    super(rest)
    this.secret = new TextEncoder().encode(secret)
  }

  async signToken(token: SignJWT): Promise<string> {
    return await token.setProtectedHeader({ alg: "HS256" }).sign(this.secret)
  }

  async verifyToken(payload: string | Uint8Array, options: JWTVerifyOptions): Promise<JWTVerifyResult> {
    return await jwtVerify(payload, this.secret, options)
  }
}
