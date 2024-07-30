import type { JWTVerifyOptions, JWTVerifyResult, SignJWT } from "jose"

export type TokenAuthorityOptions = object

export abstract class TokenAuthority {
  protected constructor(options: TokenAuthorityOptions = {}) {}

  public abstract signToken(token: SignJWT): Promise<string>
  public abstract verifyToken(payload: string | Uint8Array, options: JWTVerifyOptions): Promise<JWTVerifyResult>
}
