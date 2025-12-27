/**
 * @typedef {{ type: 'EmailEmpty' }} ValidationError_EmailEmpty
 */

/**
 * @typedef {{ type: 'EmailTooLong' }} ValidationError_EmailTooLong
 */

/**
 * @typedef {{ type: 'EmailInvalidFormat' }} ValidationError_EmailInvalidFormat
 */

/**
 * @typedef {{ type: 'PasswordEmpty' }} ValidationError_PasswordEmpty
 */

/**
 * @typedef {{ type: 'PasswordTooShort', value: number }} ValidationError_PasswordTooShort
 */

/**
 * @typedef {{ type: 'PasswordTooLong', value: number }} ValidationError_PasswordTooLong
 */

/**
 * @typedef {{ type: 'PasswordMissingUppercase' }} ValidationError_PasswordMissingUppercase
 */

/**
 * @typedef {{ type: 'PasswordMissingLowercase' }} ValidationError_PasswordMissingLowercase
 */

/**
 * @typedef {{ type: 'PasswordMissingDigit' }} ValidationError_PasswordMissingDigit
 */

/**
 * @typedef {{ type: 'PasswordMissingSpecial' }} ValidationError_PasswordMissingSpecial
 */

/**
 * @typedef {{ type: 'PasswordCommon' }} ValidationError_PasswordCommon
 */

/**
 * @typedef {{ type: 'PasswordCustom', value: string }} ValidationError_PasswordCustom
 */

/**
 * @typedef {{ type: 'NameEmpty' }} ValidationError_NameEmpty
 */

/**
 * @typedef {{ type: 'NameTooLong' }} ValidationError_NameTooLong
 */

/**
 * @typedef {(ValidationError_EmailEmpty | ValidationError_EmailTooLong | ValidationError_EmailInvalidFormat | ValidationError_PasswordEmpty | ValidationError_PasswordTooShort | ValidationError_PasswordTooLong | ValidationError_PasswordMissingUppercase | ValidationError_PasswordMissingLowercase | ValidationError_PasswordMissingDigit | ValidationError_PasswordMissingSpecial | ValidationError_PasswordCommon | ValidationError_PasswordCustom | ValidationError_NameEmpty | ValidationError_NameTooLong)} ValidationError
 */
