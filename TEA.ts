/**
 * @author Chris Veness © 2000-2005
 * @website https://www.movable-type.co.uk/scripts/tea.html
 *
 * @author Paul Schmeing
 * @website https://veenixdev.github.io
 *
 *  Changes made by Paul Schmeing:
 *    - Added Typescript compatability
 *    - Made into a class
 *    - documented
 *    - cleaned up
 *    - added possibility to use password caching
 *
 *  This class contains the Tiny Encription Algorithm(short = TEA).
 *  The TEA is a short and fast algorithm to encode and decode text.
 */
export default class TinyEncryptionAlgorithm {
	private static delta = 0x9e3779b9;

	public password: Array<number> = new Array(4);

	constructor(password: string) {
		for (let i = 0; i < 4; i++)
			this.password[i] = TinyEncryptionAlgorithm.Str4ToLong(
				password.slice(i * 4, (i + 1) * 4)
			);
	}

	/**
	 * @author See Class auhtors
	 *
	 * @since 01.05.2021
	 *
	 * @param plaintext The text that should get encrypted.
	 * @param password The password with which you will be able to decrypt the encrypted text(= chiphertext)
	 * @returns The chiphertext(= encrypted text)
	 * @throws "Object doesn't support this property or method" if 'password' or 'plaintext' are passes as string objects rather than strings
	 *
	 * use (16 chars of) 'password' to encrypt 'plaintext'
	 */
	public static encrypt(plaintext: string, password: string): string {
		let v: Array<number> = new Array(2),
			k: Array<number> = new Array(4),
			s: string = '',
			i: number;

		plaintext = escape(plaintext); // use escape() so only have single-byte chars to encode

		// build key directly from 1st 16 chars of password
		for (let i = 0; i < 4; i++)
			k[i] = this.Str4ToLong(password.slice(i * 4, (i + 1) * 4));

		for (i = 0; i < plaintext.length; i += 8) {
			// encode plaintext into s in 64-bit (8 char) blocks
			v[0] = this.Str4ToLong(plaintext.slice(i, i + 4)); // ... note this is 'electronic codebook' mode
			v[1] = this.Str4ToLong(plaintext.slice(i + 4, i + 8));
			this.code(v, k);
			s += this.LongToStr4(v[0]) + this.LongToStr4(v[1]);
		}

		return this.escCtrlCh(s);
	}

	/**
	 * @author See Class auhtors
	 *
	 * @since 01.05.2021
	 *
	 * @param plaintext The text that should get encrypted.
	 * @returns The chiphertext(= encrypted text)
	 * @throws "Object doesn't support this property or method" if 'password' or 'plaintext' are passes as string objects rather than strings
	 *
	 * use (16 chars of) 'password' to encrypt 'plaintext'
	 */
	public encrypt(plaintext: string): string {
		let v: Array<number> = new Array(2),
			s: string = '',
			i: number;

		plaintext = escape(plaintext); // use escape() so only have single-byte chars to encode

		for (i = 0; i < plaintext.length; i += 8) {
			// encode plaintext into s in 64-bit (8 char) blocks
			v[0] = TinyEncryptionAlgorithm.Str4ToLong(plaintext.slice(i, i + 4)); // ... note this is 'electronic codebook' mode
			v[1] = TinyEncryptionAlgorithm.Str4ToLong(plaintext.slice(i + 4, i + 8));
			TinyEncryptionAlgorithm.code(v, this.password);
			s +=
				TinyEncryptionAlgorithm.LongToStr4(v[0]) +
				TinyEncryptionAlgorithm.LongToStr4(v[1]);
		}

		return TinyEncryptionAlgorithm.escCtrlCh(s);
	}

	/**
	 * It does the same thing as the static method but is optimized,
	 * its won't compute k everytime but instead take it from the instance.
	 *
	 * Because of the optimisation you are required to first create a instance of TinyEncryptionAlgorithm
	 *
	 * @since 03.05.2021
	 *
	 * @param ciphertext
	 * @returns
	 */
	public decrypt(ciphertext: string): string {
		let v: Array<number> = new Array(2),
			s: string = '',
			i: number;

		ciphertext = TinyEncryptionAlgorithm.unescCtrlCh(ciphertext);
		for (i = 0; i < ciphertext.length; i += 8) {
			// decode ciphertext into s in 64-bit (8 char) blocks
			v[0] = TinyEncryptionAlgorithm.Str4ToLong(ciphertext.slice(i, i + 4));
			v[1] = TinyEncryptionAlgorithm.Str4ToLong(ciphertext.slice(i + 4, i + 8));
			TinyEncryptionAlgorithm.decode(v, this.password);
			s +=
				TinyEncryptionAlgorithm.LongToStr4(v[0]) +
				TinyEncryptionAlgorithm.LongToStr4(v[1]);
		}

		// strip trailing null chars resulting from filling 4-char blocks:
		s = s.replace(/\0+$/, '');

		return unescape(s);
	}

	/**
	 * @author See Class auhtors
	 *
	 * @since 01.05.2021
	 *
	 * @param ciphertext The encrypted text you want to decrypt.
	 * @param password The password used to encrypt the text.
	 * @returns The text in plaintext without encryption
	 *
	 * Use (16 chars of) 'password' to decrypt 'ciphertext' with xTEA
	 */
	public static decrypt(ciphertext: string, password: string): string {
		let v: Array<number> = new Array(2),
			k: Array<number> = new Array(4),
			s: string = '',
			i: number;

		for (let i = 0; i < 4; i++)
			k[i] = this.Str4ToLong(password.slice(i * 4, (i + 1) * 4));

		ciphertext = this.unescCtrlCh(ciphertext);
		for (i = 0; i < ciphertext.length; i += 8) {
			// decode ciphertext into s in 64-bit (8 char) blocks
			v[0] = this.Str4ToLong(ciphertext.slice(i, i + 4));
			v[1] = this.Str4ToLong(ciphertext.slice(i + 4, i + 8));
			this.decode(v, k);
			s += this.LongToStr4(v[0]) + this.LongToStr4(v[1]);
		}

		// strip trailing null chars resulting from filling 4-char blocks:
		s = s.replace(/\0+$/, '');

		return unescape(s);
	}

	/**
	 * @author See Class auhtors
	 * @helper Karsten Kraus
	 *
	 * @since 01.05.2021
	 *
	 * @See "encrypt()" to see how 'v' and 'k' are generated
	 *
	 * @param v The plaintext in form of an Array
	 * @param k The password in form of an Array
	 *
	 * Extended TEA: this is the 1997 revised version of Needham & Wheeler's algorithm
	 * params: v[2] 64-bit value block; k[4] 128-bit key
	 */
	private static code(v: Array<number>, k: Array<number>): void {
		let y = v[0],
			z = v[1];
		let limit = this.delta * 32,
			sum = 0;

		while (sum != limit) {
			y += (((z << 4) ^ (z >>> 5)) + z) ^ (sum + k[sum & 3]);
			sum += this.delta;
			z += (((y << 4) ^ (y >>> 5)) + y) ^ (sum + k[(sum >>> 11) & 3]);
			// note: unsigned right-shift '>>>' is used in place of original '>>', due to lack
			// of 'unsigned' type declaration in JavaScript
		}
		v[0] = y;
		v[1] = z;
	}

	/**
	 * @author See Class auhtors
	 * @helper Karsten Kraus
	 *
	 * @since 01.05.2021
	 *
	 * @See "decrypt()" to see how 'v' and 'k' are generated
	 *
	 * @param v The ciphertext in form of an Array
	 * @param k The password in form of an Array
	 */
	private static decode(v: Array<number>, k: Array<number>): void {
		let y = v[0],
			z = v[1];
		let sum = this.delta * 32;

		while (sum != 0) {
			z -= (((y << 4) ^ (y >>> 5)) + y) ^ (sum + k[(sum >>> 11) & 3]);
			sum -= this.delta;
			y -= (((z << 4) ^ (z >>> 5)) + z) ^ (sum + k[sum & 3]);
		}
		// note: unsigned right-shift '>>>' is used in place of original '>>', due to lack
		// of 'unsigned' type declaration in JavaScript

		v[0] = y;
		v[1] = z;
	}

	// ------ supporting functions ------

	/**
	 * @author See Class auhtors
	 *
	 * @since 01.05.2021
	 *
	 * @param s The string that gets converted to a number
	 * @returns The string in form of a number
	 *
	 * convert 4 chars of s to a numeric long
	 */
	private static Str4ToLong(str: string): number {
		let v = 0;
		for (let i = 0; i < 4; i++) v |= str.charCodeAt(i) << (i * 8);
		return isNaN(v) ? 0 : v;
	}

	/**
	 * @author See Class auhtors
	 *
	 * @since 01.05.2021
	 *
	 * @param l The number that gets converted to a string
	 * @returns The number in form of a string
	 *
	 * convert a numeric long to 4 char string
	 */
	private static LongToStr4(l: number): string {
		return String.fromCharCode(
			l & 0xff,
			(l >> 8) & 0xff,
			(l >> 16) & 0xff,
			(l >> 24) & 0xff
		);
	}

	/**
	 * @author See Class auhtors
	 *
	 * @since 01.05.2021
	 *
	 * @param str The string you want to escape control
	 * @returns The string with escape control
	 *
	 * escape control chars which might cause problems with encrypted texts
	 */
	private static escCtrlCh(str: string): string {
		return str.replace(
			/[\0\t\n\v\f\r\xa0'"!]/g,
			(c: any) => '!' + c.charCodeAt(0) + '!'
		);
	}

	/**
	 * @author See Class auhtors
	 *
	 * @since 01.05.2021
	 *
	 * @param str The string you want to unescape problematic characters
	 * @returns The unescaped string
	 *
	 * unescape potentially problematic nulls and control characters
	 */
	private static unescCtrlCh(str: string): string {
		return str.replace(/!\d\d?\d?!/g, (c: any) =>
			String.fromCharCode(c.slice(1, -1))
		);
	}
}
