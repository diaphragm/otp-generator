# frozen_string_literal: true

require 'bundler/setup'
require 'rotp'
require 'yaml'
require 'io/console'
require 'uri'
require_relative 'crypter'

class App
  def initialize(filename: 'data/data.yml')
    @filename = filename
    command_exec
  end

  def command_exec
    case ARGV.length
    when 2
      otp_name = ARGV[0]
      parsed = parse_scheme(ARGV[1])
      secret = parsed&.[]('secret') || ARGV[1]
      register_otp(secret, otp_name)
    when 1
      otp_name = ARGV[0]
      generate_otp(otp_name)
    when 0
      generate_all_otp
    else
      puts 'Bad Parameter'
    end
  end

  def parse_scheme(otp_scheme)
    uri = URI.parse(otp_scheme)
    if uri.scheme == 'otpauth'
      query = URI.decode_www_form(uri.query).to_h
      query['accountname'] = uri.path.slice(/(?<=:).*/)
      query['type'] = uri.host
      query
    end
  end

  def register_otp(secret, otp_name)
    load
    salt = @data[:salt]

    enc = Crypter.new(password, salt)
    enc_secret = enc.encrypt(secret)
    @data[:secrets][otp_name] = enc_secret

    save
    puts "Secret data for #{otp_name} saved."
  end

  def generate_otp(otp_name)
    load
    salt = @data[:salt]
    raise 'No Salt Data' if salt.nil?
    secret_data = @data[:secrets]
    raise 'No Secrets Data' if secret_data.nil?
    enc_secret = secret_data[otp_name]
    raise "No Secret Data for `#{otp_name}'" if enc_secret.nil?

    dec = Crypter.new(password, salt)
    secret = dec.decrypt(enc_secret)

    totp = ROTP::TOTP.new(secret)
    print "#{otp_name}: "
    puts totp.now
  end

  def generate_all_otp
    load
    salt = @data[:salt]
    raise 'No Salt Data' if salt.nil?
    secret_data = @data[:secrets]
    raise 'No Secrets Data' if secret_data.nil?
    secret_data.each_key do |otp_name|
      generate_otp(otp_name)
    rescue OpenSSL::Cipher::CipherError
      puts "password for #{otp_name}: "
      ask_password
      retry
    end
  end

  def password
    @password || ask_password
  end

  def ask_password
    print 'password: '
    @password = $stdin.noecho(&:gets).chomp
    puts
    @password
  end

  def load
    @data =
      if File.exist?(@filename)
        YAML.load_file(@filename)
      else
        {
          salt: Crypter.generate_salt,
          secrets: {},
        }
      end
  end

  def save
    File.write(@filename, YAML.dump(@data))
  end
end

App.new
