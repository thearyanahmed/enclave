export type ValidationError =
  | { type: "EmailEmpty" }
  | { type: "EmailTooLong" }
  | { type: "EmailInvalidFormat" }
  | { type: "PasswordEmpty" }
  | { type: "PasswordTooShort"; value: number }
  | { type: "PasswordTooLong"; value: number }
  | { type: "PasswordMissingUppercase" }
  | { type: "PasswordMissingLowercase" }
  | { type: "PasswordMissingDigit" }
  | { type: "PasswordMissingSpecial" }
  | { type: "PasswordCommon" }
  | { type: "PasswordCustom"; value: string }
  | { type: "NameEmpty" }
  | { type: "NameTooLong" };
