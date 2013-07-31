////
////  RNOpenSSLCryptor
////
////  Copyright (c) 2012 Rob Napier
////
////  This code is licensed under the MIT License:
////
////  Permission is hereby granted, free of charge, to any person obtaining a
////  copy of this software and associated documentation files (the "Software"),
////  to deal in the Software without restriction, including without limitation
////  the rights to use, copy, modify, merge, publish, distribute, sublicense,
////  and/or sell copies of the Software, and to permit persons to whom the
////  Software is furnished to do so, subject to the following conditions:
////
////  The above copyright notice and this permission notice shall be included in
////  all copies or substantial portions of the Software.
////
////  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
////  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
////  FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
////  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
////  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
////  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
////  DEALINGS IN THE SOFTWARE.
////


// For aes-128:
//
// key = MD5(password + salt)
// IV = MD5(Key + password + salt)

//
// For aes-256:
//
// Hash0 = ''
// Hash1 = MD5(Hash0 + Password + Salt)
// Hash2 = MD5(Hash1 + Password + Salt)
// Hash3 = MD5(Hash2 + Password + Salt)
// Hash4 = MD5(Hash3 + Password + Salt)
//
// Key = Hash1 + Hash2
// IV = Hash3 + Hash4
//

// File Format:
//
// |Salted___|<salt>|<ciphertext>|
//

#import "RNOpenSSLCryptor.h"

NSString *const kRNCryptorOpenSSLSaltedString = @"Salted__";

static NSData *GetHashForHash(NSData *hash, NSData *passwordSalt) {
  unsigned char md[CC_MD5_DIGEST_LENGTH];

  NSMutableData *hashMaterial = [NSMutableData dataWithData:hash];
  [hashMaterial appendData:passwordSalt];
  CC_MD5([hashMaterial bytes], (CC_LONG)[hashMaterial length], md);

  return [NSData dataWithBytes:md length:sizeof(md)];
}


NSData *RNOpenSSLCryptorGetKey(NSString *password, NSData *salt, RNCryptorKeyDerivationSettings keySettings) {
  // This is all very inefficient; we repeat ourselves in IVForKey:...

  // Hash0 = ''
  // Hash1 = MD5(Hash0 + Password + Salt)
  // Hash2 = MD5(Hash1 + Password + Salt)
  // Hash3 = MD5(Hash2 + Password + Salt)
  // Hash4 = MD5(Hash3 + Password + Salt)
  //
  // Key = Hash1 + Hash2
  // IV = Hash3 + Hash4

  NSMutableData *passwordSalt = [[password dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
  [passwordSalt appendData:salt];

  NSData *hash1 = GetHashForHash(nil, passwordSalt);
  NSData *hash2 = GetHashForHash(hash1, passwordSalt);

  NSMutableData *key = [hash1 mutableCopy];
  [key appendData:hash2];

  return key;
}

NSData *RNOpenSSLCryptorGetIV(NSData *key, NSString *password, NSData *salt, RNCryptorKeyDerivationSettings keySettings) {
  NSCAssert(keySettings.keySize == kCCKeySizeAES256, @"OpenSSL uses a different mechanism for AES128. Implement if needed. key is needed for AES128");

  NSMutableData *passwordSalt = [[password dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
  [passwordSalt appendData:salt];

  NSData *hash1 = GetHashForHash(nil, passwordSalt);
  NSData *hash2 = GetHashForHash(hash1, passwordSalt);
  NSData *hash3 = GetHashForHash(hash2, passwordSalt);
  NSData *hash4 = GetHashForHash(hash3, passwordSalt);

  NSMutableData *IV = [hash3 mutableCopy];
  [IV appendData:hash4];

  return IV;
}


