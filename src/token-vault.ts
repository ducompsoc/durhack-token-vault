import { type JWTPayload, type JWTVerifyResult, SignJWT } from "jose"
import ModuleError from "module-error"

import type { TokenAuthority } from "@/authorities/base"
import { epoch } from "@/util"

import { TokenError } from "./jwt-error"
import { TokenType } from "./token-type"

export type TokenOptions = {
  scope?: string[]
  lifetime?: string | number
  claims?: { [key: string]: unknown }
}

export type TokenVaultOptions<TUser> = {
  getUserIdentifier: (user: TUser) => string | number
  findUniqueUser: (userId: string | number) => Promise<TUser | null> | TUser | null
  issuer: string
  audience: string
  accessTokenLifetime?: number
  refreshTokenLifetime?: number
}

export class TokenVault<TUser> {
  authorities: Map<TokenType, TokenAuthority>
  getUserIdentifier: (user: TUser) => string | number
  findUniqueUser: (userId: string | number) => Promise<TUser | null> | TUser | null
  issuer: string
  audience: string
  accessTokenLifetime: number
  refreshTokenLifetime: number

  constructor(options: TokenVaultOptions<TUser>) {
    this.authorities = new Map()
    this.getUserIdentifier = options.getUserIdentifier
    this.findUniqueUser = options.findUniqueUser
    this.issuer = options.issuer
    this.audience = options.audience
    this.accessTokenLifetime = options.accessTokenLifetime ?? 1800
    this.refreshTokenLifetime = options.refreshTokenLifetime ?? 1209600
  }

  public registerAuthority(type: TokenType, authority: TokenAuthority) {
    this.authorities.set(type, authority)
  }

  public async createToken(type: TokenType, user: TUser, options: TokenOptions): Promise<string> {
    let { scope, lifetime, claims } = options

    scope ??= this.getDefaultTokenScope(type)
    lifetime ??= this.getDefaultTokenLifetime(type)
    claims ??= {}

    const corePayload = { userId: this.getUserIdentifier(user), scope: scope }

    const expiry = this.lifetimeToExpiry(lifetime)
    const token = new SignJWT({ ...claims, ...corePayload }).setIssuedAt().setExpirationTime(expiry)

    token.setIssuer(this.issuer).setAudience(this.audience)

    return await this.getTokenAuthority(type).signToken(token)
  }

  public async decodeToken(type: TokenType, payload: string | Uint8Array): Promise<JWTVerifyResult> {
    const authority = this.authorities.get(type)
    if (typeof authority === "undefined")
      throw new ModuleError("No registered authority for token type.", {
        code: "ERR_NO_REGISTERED_AUTHORITY",
      })
    return await authority.verifyToken(payload, {
      issuer: this.issuer,
      audience: this.audience,
    })
  }

  public async getUserAndScopeClaims(payload: JWTPayload): Promise<{ user: TUser; scope: string[] }> {
    const { userId, scope } = payload

    if (typeof userId !== "string") {
      throw new TokenError("Invalid user ID", {
        code: "ERR_TOKEN_USER_ID_INVALID"
      })
    }

    if (!(Array.isArray(scope) && scope.every((e) => typeof e === "string"))) {
      throw new TokenError("Invalid scope", {
        code: "ERR_TOKEN_SCOPE_INVALID"
      })
    }

    const user = await this.findUniqueUser(userId)
    if (user == null)
      throw new ModuleError("User not found.", {
        code: "ERR_USER_NOT_FOUND",
      })

    return { user, scope }
  }

  public async createAccessToken(user: TUser, options: TokenOptions): Promise<string> {
    return await this.createToken(TokenType.accessToken, user, options)
  }

  public async createRefreshToken(user: TUser, options: TokenOptions): Promise<string> {
    return await this.createToken(TokenType.refreshToken, user, options)
  }

  private getDefaultTokenScope(type: TokenType): string[] {
    if (type === TokenType.accessToken) {
      return ["api"]
    }

    if (type === TokenType.refreshToken) {
      return ["refresh"]
    }

    if (type === TokenType.authorizationCode) {
      return []
    }

    throw new ModuleError("Unknown token type.", {
      code: "ERR_UNKNOWN_TOKEN_TYPE"
    })
  }

  private getDefaultTokenLifetime(type: TokenType): number {
    if (type === TokenType.accessToken) {
      return this.accessTokenLifetime
    }

    if (type === TokenType.refreshToken) {
      return this.refreshTokenLifetime
    }

    if (type === TokenType.authorizationCode) {
      return 60
    }

    throw new ModuleError("Unknown token type.", {
      code: "ERR_UNKNOWN_TOKEN_TYPE"
    })
  }

  public lifetimeToExpiry(lifetime: number | string): number | string {
    if (typeof lifetime === "string") return lifetime
    return epoch(new Date()) + lifetime
  }

  private getTokenAuthority(type: TokenType): TokenAuthority {
    const authority = this.authorities.get(type)
    if (typeof authority === "undefined")
      throw new ModuleError("No registered authority for token type.", {
        code: "ERR_NO_REGISTERED_AUTHORITY",
      })
    return authority
  }
}
