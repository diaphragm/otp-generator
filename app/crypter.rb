require 'openssl'
require 'base64'

class Crypter
  def self.generate_salt
    Base64.encode64(OpenSSL::Random.random_bytes(8)).chomp
  end

  def initialize(password, salt_base64, algorithm: 'AES-256-CBC')
    @password = password
    @salt_base64 = salt_base64
    @algorithm = algorithm
  end

  def password
    @password
  end

  def salt
    Base64.decode64(@salt_base64)
  end

  def encrypt(plaintext)
    enc = OpenSSL::Cipher.new(@algorithm)
    enc.encrypt
    key_iv = OpenSSL::PKCS5.pbkdf2_hmac_sha1(
      password, salt, 2024, enc.key_len + enc.iv_len
    )
    enc.key = key_iv[0, enc.key_len]
    enc.iv = key_iv[enc.key_len, enc.iv_len]

    encrypt_data = ''
    encrypt_data << enc.update(plaintext)
    encrypt_data << enc.final

    Base64.encode64(encrypt_data).chomp
  end

  def decrypt(ciphertext)
    encrypt_data = Base64.decode64(ciphertext)

    dec = OpenSSL::Cipher.new(@algorithm)
    dec.decrypt
    key_iv = OpenSSL::PKCS5.pbkdf2_hmac_sha1(
      password, salt, 2024, dec.key_len + dec.iv_len
    )
    dec.key = key_iv[0, dec.key_len]
    dec.iv = key_iv[dec.key_len, dec.iv_len]

    decrypt_data = ''
    decrypt_data << dec.update(encrypt_data)
    decrypt_data << dec.final
  end
end
