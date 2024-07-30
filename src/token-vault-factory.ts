import type { TokenAuthority } from "@/authorities/base"
import {type TokenAuthorityConfig, getAuthority, FilePathResolver} from "@/authority-factory"
import type { TokenType } from "@/token-type"
import { TokenVault, type TokenVaultOptions } from "@/token-vault"

export type TokenVaultConfig<TUser> = TokenVaultOptions<TUser> & {
  filePathResolver?: FilePathResolver
  authorities: TokenAuthorityConfig[]
}

export async function getTokenVault<TUser>({ authorities, filePathResolver, ...options }: TokenVaultConfig<TUser>): Promise<TokenVault<TUser>> {
  const authoritiesWithInfo: Array<{ for: TokenType; authority: TokenAuthority }> = await Promise.all(
    authorities.map(async (authority) => {
      return await getAuthority({ filePathResolver, ...authority })
    }),
  )

  const vault = new TokenVault(options)

  for (const { for: authorityFor, authority } of authoritiesWithInfo) {
    vault.registerAuthority(authorityFor, authority)
  }

  return vault
}
