export interface JwtClaims {
  sub: string;
  exp: number;
  iat: number;
  jti: string;
  token_type: TokenType;
  iss?: string | null;
  aud?: string | null;
}
