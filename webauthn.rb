# Spinel bundled `webauthn`: the relying-party half of the webauthn gem
# (cedarcode/webauthn-ruby 3.4.3), in its class names and with its answers.
#
# What a passkey login needs is here: the creation and request options and
# their JSON, a registration (`from_create` + `verify`) and an assertion
# (`from_get` + `verify`) checked the way the gem checks them -- client data
# type, challenge, origin and token binding, the RP id hash, the user present
# and user verified flags, the attested credential, the attestation statement,
# the signature and the sign count -- and the gem's errors, whose messages
# are the class names it raises them with.
#
# The gem builds on four others (cbor, cose, bindata and
# openssl-signature_algorithm); the parts of them this needs are written out
# below rather than ported whole: a CBOR decoder, COSE keys and the
# signature algorithms the gem enables by default (ES256, PS256, RS256). The
# signatures themselves are checked by the openssl package (ECDSA, RSA
# PKCS#1 v1.5 and PSS over the system libcrypto).
#
# Attestation: "none" and "packed" self attestation are verified as the gem
# verifies them. Every other format, and packed with a certificate chain,
# needs X.509 parsing and root certificates this package does not have: they
# raise AttestationStatementVerificationError, which is also what the gem
# answers for them under its default configuration (no root certificate
# finders), except "apple" and "android-key", which the gem can check against
# roots it bundles. A browser asked for `attestation: "none"` (the gem's
# default) sends "none".
require "json"
require "securerandom"
require "digest"
require "openssl"
require "uri"

module WebAuthn
  TYPE_PUBLIC_KEY = "public-key"
  TYPES = { create: "webauthn.create", get: "webauthn.get" }.freeze

  class Error < StandardError; end
  class RootCertificateFinderNotSupportedError < Error; end
  class ClientDataMissingError < Error; end
  class AuthenticatorDataFormatError < Error; end
  class AttestedCredentialDataFormatError < Error; end

  class VerificationError < Error; end
  class AuthenticatorDataVerificationError < VerificationError; end
  class ChallengeVerificationError < VerificationError; end
  class OriginVerificationError < VerificationError; end
  class RpIdVerificationError < VerificationError; end
  class TokenBindingVerificationError < VerificationError; end
  class TypeVerificationError < VerificationError; end
  class UserPresenceVerificationError < VerificationError; end
  class UserVerifiedVerificationError < VerificationError; end
  class AttestationStatementVerificationError < VerificationError; end
  class AttestedCredentialVerificationError < VerificationError; end
  class SignatureVerificationError < VerificationError; end
  class SignCountVerificationError < VerificationError; end

  def self.generate_user_id
    configuration.encoder.encode(SecureRandom.random_bytes(64))
  end

  def self.configuration
    @configuration ||= Configuration.new
  end

  def self.configure
    yield(configuration)
  end

  def self.standard_encoder
    Encoders::Base64UrlEncoder
  end

  # The gem's comparison for secrets: equal lengths, then every byte, with
  # no early exit (OpenSSL.secure_compare hashes both first; comparing the
  # digests is the same answer).
  def self.secure_compare(a, b)
    da = Digest::SHA256.digest(a)
    db = Digest::SHA256.digest(b)
    diff = 0
    i = 0
    while i < da.bytesize
      diff |= da.getbyte(i) ^ db.getbyte(i)
      i += 1
    end
    diff == 0 && a == b
  end

  module Encoders
    def self.lookup(encoding)
      case encoding
      when :base64 then Base64Encoder
      when :base64url then Base64UrlEncoder
      when nil, false then NullEncoder
      else raise "Unsupported or unknown encoding: #{encoding}"
      end
    end

    class Base64Encoder
      def self.encode(data)
        [data].pack("m0")
      end

      def self.decode(data)
        data.unpack1("m0")
      end
    end

    class Base64UrlEncoder
      def self.encode(data)
        out = [data].pack("m0")
        out = out.chomp("=").chomp("=")
        out.tr("+/", "-_")
      end

      def self.decode(data)
        if !data.end_with?("=") && data.length % 4 != 0
          data = data.ljust((data.length + 3) & ~3, "=")
        end
        data.tr("-_", "+/").unpack1("m0")
      end
    end

    class NullEncoder
      def self.encode(data)
        data
      end

      def self.decode(data)
        data
      end
    end
  end

  class Encoder
    STANDARD_ENCODING = :base64url

    def initialize(encoding = STANDARD_ENCODING)
      @encoding = encoding
      Encoders.lookup(encoding)
    end

    def encode(data)
      case @encoding
      when :base64 then Encoders::Base64Encoder.encode(data)
      when nil, false then data
      else Encoders::Base64UrlEncoder.encode(data)
      end
    end

    def decode(data)
      case @encoding
      when :base64 then Encoders::Base64Encoder.decode(data)
      when nil, false then data
      else Encoders::Base64UrlEncoder.decode(data)
      end
    end
  end

  class RelyingParty
    DEFAULT_ALGORITHMS = ["ES256", "PS256", "RS256"].freeze

    attr_accessor :algorithms, :encoding, :allowed_origins, :id, :name,
                  :verify_attestation_statement, :credential_options_timeout,
                  :silent_authentication, :acceptable_attestation_types, :legacy_u2f_appid

    def initialize
      @algorithms = DEFAULT_ALGORITHMS.dup
      @encoding = Encoder::STANDARD_ENCODING
      @allowed_origins = nil
      @id = nil
      @name = nil
      @verify_attestation_statement = true
      @credential_options_timeout = 120000
      @silent_authentication = false
      @acceptable_attestation_types = ["None", "Self", "Basic", "AttCA", "Basic_or_AttCA", "AnonCA"]
      @legacy_u2f_appid = nil
      @encoder = nil
    end

    def encoder
      @encoder ||= Encoder.new(encoding)
    end

    def encoding=(value)
      @encoding = value
      @encoder = nil
    end

    # The gem's deprecated single origin; a configuration that sets it gets
    # it as the one allowed origin.
    def origin=(new_origin)
      return if new_origin.nil?
      @allowed_origins ||= [new_origin]
    end

    def origin
      allowed_origins.first if allowed_origins && allowed_origins.size == 1
    end
  end

  class Configuration
    attr_reader :relying_party

    def initialize
      @relying_party = RelyingParty.new
    end

    def rp_name = relying_party.name
    def rp_name=(name)
      relying_party.name = name
    end

    def rp_id = relying_party.id
    def rp_id=(id)
      relying_party.id = id
    end

    def allowed_origins = relying_party.allowed_origins
    def allowed_origins=(origins)
      relying_party.allowed_origins = origins
    end

    def origin = relying_party.origin
    def origin=(origin)
      relying_party.origin = origin
    end

    def algorithms = relying_party.algorithms
    def algorithms=(algorithms)
      relying_party.algorithms = algorithms
    end

    def encoding = relying_party.encoding
    def encoding=(encoding)
      relying_party.encoding = encoding
    end

    def encoder = relying_party.encoder

    def credential_options_timeout = relying_party.credential_options_timeout
    def credential_options_timeout=(timeout)
      relying_party.credential_options_timeout = timeout
    end

    def silent_authentication = relying_party.silent_authentication
    def silent_authentication=(value)
      relying_party.silent_authentication = value
    end

    def verify_attestation_statement = relying_party.verify_attestation_statement
    def verify_attestation_statement=(value)
      relying_party.verify_attestation_statement = value
    end

    def acceptable_attestation_types = relying_party.acceptable_attestation_types
    def acceptable_attestation_types=(types)
      relying_party.acceptable_attestation_types = types
    end

    def legacy_u2f_appid = relying_party.legacy_u2f_appid
    def legacy_u2f_appid=(appid)
      relying_party.legacy_u2f_appid = appid
    end
  end

  # The `as_json` the gem's options answer (its JSONSerializer): the
  # attributes in order, nil ones left out, keys camelized into Symbols.
  module JSONSerializer
    def self.camelize(key)
      parts = key.to_s.split("_")
      out = parts[0].to_s
      i = 1
      while i < parts.length
        out += parts[i].capitalize
        i += 1
      end
      out.to_sym
    end

    def self.deep_camelize(value)
      if value.is_a?(Hash)
        out = {}
        value.each { |k, v| out[camelize(k)] = deep_camelize(v) }
        out
      elsif value.is_a?(Array)
        value.map { |v| deep_camelize(v) }
      else
        value
      end
    end
  end

  class PublicKeyCredential
    class InvalidChallengeError < Error; end

    class RPEntity
      attr_reader :name, :id

      def initialize(name: nil, id: nil)
        @name = name
        @id = id
      end

      def as_json(*)
        out = {}
        out[:name] = name if name
        out[:id] = id if id
        out
      end
    end

    class UserEntity
      attr_reader :name, :id, :display_name

      def initialize(id:, name: nil, display_name: nil)
        @id = id
        @name = name
        @display_name = display_name || name
      end

      def as_json(*)
        out = {}
        out[:name] = name if name
        out[:id] = id if id
        out[:displayName] = display_name if display_name
        out
      end
    end

    class Options
      CHALLENGE_LENGTH = 32

      attr_reader :timeout, :extensions, :relying_party

      def initialize(timeout: nil, extensions: nil, relying_party: WebAuthn.configuration.relying_party)
        @relying_party = relying_party
        @timeout = timeout || relying_party.credential_options_timeout
        @extensions = (extensions || {})
        @raw_challenge = nil
      end

      def challenge
        relying_party.encoder.encode(raw_challenge)
      end

      def raw_challenge
        @raw_challenge ||= SecureRandom.random_bytes(CHALLENGE_LENGTH)
      end

      private

      def as_public_key_descriptors(ids)
        ids.map { |id| { type: TYPE_PUBLIC_KEY, id: id } }
      end

      def base_json
        out = {}
        out[:challenge] = challenge
        out[:timeout] = timeout if timeout
        out[:extensions] = JSONSerializer.deep_camelize(extensions)
        out
      end
    end

    class CreationOptions < Options
      attr_accessor :attestation, :authenticator_selection, :exclude, :algs, :rp, :user

      def initialize(user:, attestation: nil, authenticator_selection: nil, exclude_credentials: nil,
                     exclude: nil, pub_key_cred_params: nil, algs: nil, rp: nil,
                     timeout: nil, extensions: nil, relying_party: WebAuthn.configuration.relying_party)
        super(timeout: timeout, extensions: extensions, relying_party: relying_party)
        @attestation = attestation
        @authenticator_selection = authenticator_selection
        @exclude_credentials = exclude_credentials
        @exclude = exclude
        @pub_key_cred_params = pub_key_cred_params
        @algs = algs
        rp_hash = rp || {}
        @rp = RPEntity.new(name: rp_hash[:name] || relying_party.name, id: rp_hash[:id] || relying_party.id)
        @user = UserEntity.new(id: user[:id], name: user[:name], display_name: user[:display_name])
      end

      def exclude_credentials
        @exclude_credentials || (exclude ? as_public_key_descriptors(Array(exclude)) : nil)
      end

      def pub_key_cred_params
        @pub_key_cred_params || Array(algs || relying_party.algorithms).map do |alg|
          { type: TYPE_PUBLIC_KEY, alg: COSE::Algorithm.id_of(alg) }
        end
      end

      def as_json(*)
        out = base_json
        out[:rp] = rp.as_json
        out[:user] = user.as_json
        out[:pubKeyCredParams] = JSONSerializer.deep_camelize(pub_key_cred_params)
        out[:attestation] = attestation if attestation
        out[:authenticatorSelection] = JSONSerializer.deep_camelize(authenticator_selection) if authenticator_selection
        ex = exclude_credentials
        out[:excludeCredentials] = JSONSerializer.deep_camelize(ex) if ex
        out
      end
    end

    class RequestOptions < Options
      attr_accessor :rp_id, :allow, :user_verification

      def initialize(rp_id: nil, allow_credentials: nil, allow: nil, user_verification: nil,
                     timeout: nil, extensions: nil, relying_party: WebAuthn.configuration.relying_party)
        super(timeout: timeout, extensions: extensions, relying_party: relying_party)
        @rp_id = rp_id || relying_party.id
        @allow_credentials = allow_credentials
        @allow = allow
        @user_verification = user_verification
        if relying_party.legacy_u2f_appid
          @extensions = @extensions.merge(appid: relying_party.legacy_u2f_appid)
        end
      end

      def allow_credentials
        @allow_credentials || (allow ? as_public_key_descriptors(Array(allow)) : nil) || []
      end

      def as_json(*)
        out = base_json
        out[:allowCredentials] = JSONSerializer.deep_camelize(allow_credentials)
        out[:rpId] = rp_id if rp_id
        out[:userVerification] = user_verification if user_verification
        out
      end
    end

    attr_reader :type, :id, :raw_id, :client_extension_outputs, :authenticator_attachment, :response

    def initialize(type:, id:, raw_id:, response:, authenticator_attachment: nil,
                   client_extension_outputs: nil, relying_party: WebAuthn.configuration.relying_party)
      @type = type
      @id = id
      @raw_id = raw_id
      @client_extension_outputs = client_extension_outputs
      @authenticator_attachment = authenticator_attachment
      @response = response
      @relying_party = relying_party
    end

    def verify_credential(challenge)
      unless challenge.is_a?(String)
        raise InvalidChallengeError, "challenge must be a String. input challenge class: #{challenge.class}"
      end
      raise "invalid type" unless type == TYPE_PUBLIC_KEY
      raise "invalid id" unless raw_id && id && raw_id == WebAuthn.standard_encoder.decode(id)
      true
    end

    def encoder
      @relying_party.encoder
    end
  end

  module Credential
    def self.options_for_create(user:, attestation: nil, authenticator_selection: nil, exclude_credentials: nil,
                                exclude: nil, pub_key_cred_params: nil, algs: nil, rp: nil, timeout: nil,
                                extensions: nil, relying_party: WebAuthn.configuration.relying_party)
      PublicKeyCredential::CreationOptions.new(
        user: user, attestation: attestation, authenticator_selection: authenticator_selection,
        exclude_credentials: exclude_credentials, exclude: exclude, pub_key_cred_params: pub_key_cred_params,
        algs: algs, rp: rp, timeout: timeout, extensions: extensions, relying_party: relying_party
      )
    end

    def self.options_for_get(rp_id: nil, allow_credentials: nil, allow: nil, user_verification: nil,
                             timeout: nil, extensions: nil, relying_party: WebAuthn.configuration.relying_party)
      PublicKeyCredential::RequestOptions.new(
        rp_id: rp_id, allow_credentials: allow_credentials, allow: allow, user_verification: user_verification,
        timeout: timeout, extensions: extensions, relying_party: relying_party
      )
    end

    def self.from_create(credential, relying_party: WebAuthn.configuration.relying_party)
      PublicKeyCredentialWithAttestation.from_client(credential, relying_party: relying_party)
    end

    def self.from_get(credential, relying_party: WebAuthn.configuration.relying_party)
      PublicKeyCredentialWithAssertion.from_client(credential, relying_party: relying_party)
    end
  end

  # A minimal CBOR decoder (RFC 8949): what attestation objects, attestation
  # statements, COSE keys and extension outputs are made of. Byte strings
  # come back as binary Strings, text strings as UTF-8 ones. `decode_with_length`
  # also answers how many bytes the first item took, which is how the gem
  # finds where a credential's public key ends.
  module CBOR
    class MalformedFormatError < StandardError; end

    def self.decode(bytes)
      decode_with_length(bytes)[0]
    end

    def self.decode_with_length(bytes)
      reader = Reader.new(bytes.b)
      value = reader.item
      [value, reader.offset]
    end

    class Reader
      def initialize(bytes)
        @bytes = bytes
        @offset = 0
      end

      def offset
        @offset
      end

      def byte
        at = @offset
        raise MalformedFormatError, "end of data" if at >= @bytes.bytesize
        @offset = at + 1
        @bytes.getbyte(at)
      end

      def take(n)
        at = @offset
        raise MalformedFormatError, "end of data" if at + n > @bytes.bytesize
        @offset = at + n
        @bytes.byteslice(at, n)
      end

      def uint(info)
        if info < 24 then info
        elsif info == 24 then byte
        elsif info == 25 then (byte << 8) | byte
        elsif info == 26 then (byte << 24) | (byte << 16) | (byte << 8) | byte
        elsif info == 27
          hi = (byte << 24) | (byte << 16) | (byte << 8) | byte
          lo = (byte << 24) | (byte << 16) | (byte << 8) | byte
          (hi << 32) | lo
        else raise MalformedFormatError, "indefinite lengths are not supported"
        end
      end

      def item
        ib = byte
        major = ib >> 5
        info = ib & 0x1f
        case major
        when 0 then uint(info)
        when 1 then -1 - uint(info)
        when 2 then take(uint(info))
        when 3 then take(uint(info)).force_encoding("UTF-8")
        when 4
          n = uint(info)
          arr = []
          n.times { arr << item }
          arr
        when 5
          n = uint(info)
          h = {}
          n.times do
            k = item
            h[k] = item
          end
          h
        when 6
          uint(info)
          item
        else
          simple(info)
        end
      end

      def simple(info)
        case info
        when 20 then false
        when 21 then true
        when 22, 23 then nil
        when 25 then half_float((byte << 8) | byte)
        when 26 then take(4).unpack1("g")
        when 27 then take(8).unpack1("G")
        else raise MalformedFormatError, "unsupported simple value #{info}"
        end
      end

      def half_float(h)
        exp = (h >> 10) & 0x1f
        mant = h & 0x3ff
        val =
          if exp == 0 then mant * (2.0**-24)
          elsif exp == 31 then (mant == 0 ? Float::INFINITY : Float::NAN)
          else (mant + 1024) * (2.0**(exp - 25))
          end
        (h & 0x8000) != 0 ? -val : val
      end
    end
  end

  # COSE (RFC 8152) keys and the signature algorithms the gem registers.
  module COSE
    class Error < StandardError; end
    class UnknownKeyType < Error; end

    module Algorithm
      # id => [name, kind, digest, curve]
      TABLE = {
        -7 => ["ES256", :ecdsa, "SHA256", "prime256v1"],
        -35 => ["ES384", :ecdsa, "SHA384", "secp384r1"],
        -36 => ["ES512", :ecdsa, "SHA512", "secp521r1"],
        -47 => ["ES256K", :ecdsa, "SHA256", "secp256k1"],
        -8 => ["EdDSA", :eddsa, "", ""],
        -37 => ["PS256", :pss, "SHA256", ""],
        -38 => ["PS384", :pss, "SHA384", ""],
        -39 => ["PS512", :pss, "SHA512", ""],
        -257 => ["RS256", :pkcs1, "SHA256", ""],
        -258 => ["RS384", :pkcs1, "SHA384", ""],
        -259 => ["RS512", :pkcs1, "SHA512", ""],
        -65535 => ["RS1", :pkcs1, "SHA1", ""],
      }.freeze

      def self.name_of(id)
        row = TABLE[id]
        row ? row[0] : nil
      end

      def self.id_of(name_or_id)
        return name_or_id if name_or_id.is_a?(Integer)
        TABLE.each { |id, row| return id if row[0] == name_or_id.to_s }
        nil
      end

      # Does `alg` (an id) verify `signature` over `data` with `key`? A key of
      # the wrong kind for the algorithm, or an algorithm this package cannot
      # check, answers false, as the gem's COSE::Error rescue makes it.
      def self.verify(alg, key, signature, data)
        row = TABLE[alg]
        return false unless row
        case row[1]
        when :ecdsa
          return false unless key.is_a?(Key::EC2) && key.curve_name == row[3]
          return false if key.alg && key.alg != alg
          raw = ecdsa_raw_signature(signature, key.field_length)
          return false if raw.empty?
          OpenSSL::PKey::EC.from_public_bytes(row[3], key.point).verify_raw(row[2], raw, data)
        when :pkcs1
          return false unless key.is_a?(Key::RSA)
          OpenSSL::PKey::RSA.from_public_components(key.n, key.e).verify(row[2], signature, data)
        when :pss
          return false unless key.is_a?(Key::RSA)
          OpenSSL::PKey::RSA.from_public_components(key.n, key.e).verify_pss(row[2], signature, data, salt_length: :auto, mgf1_hash: row[2])
        else
          false
        end
      rescue OpenSSL::PKey::PKeyError
        false
      end

      # An ECDSA signature as WebAuthn carries it is DER (SEQUENCE of two
      # INTEGERs); the openssl package verifies the raw r || s. A raw one of
      # the right size is taken as is, as the gem's ECDSA verifier does.
      def self.ecdsa_raw_signature(sig, flen)
        return sig if sig.bytesize == 2 * flen
        return "" if sig.bytesize < 8 || sig.getbyte(0) != 0x30
        pos = 2
        pos += 1 if sig.getbyte(1) == 0x81
        out = +"".b
        2.times do
          return "" if pos + 2 > sig.bytesize || sig.getbyte(pos) != 0x02
          len = sig.getbyte(pos + 1)
          int = sig.byteslice(pos + 2, len)
          return "" if int.nil? || int.bytesize != len
          int = int.byteslice(1, int.bytesize - 1) while int.bytesize > flen && int.getbyte(0) == 0
          return "" if int.bytesize > flen
          out << ("\x00".b * (flen - int.bytesize)) << int
          pos += 2 + len
        end
        out
      end
    end

    module Key
      CURVES = { 1 => ["prime256v1", 32], 2 => ["secp384r1", 48], 3 => ["secp521r1", 66], 8 => ["secp256k1", 32] }.freeze

      def self.deserialize(bytes)
        from_map(CBOR.decode(bytes))
      end

      def self.from_map(map)
        raise Error, "COSE key must be a map" unless map.is_a?(Hash)
        case map[1]
        when 2 then EC2.new(alg: map[3], crv: map[-1], x: map[-2], y: map[-3])
        when 3 then RSA.new(alg: map[3], n: map[-1], e: map[-2])
        when 1 then OKP.new(alg: map[3], crv: map[-1], x: map[-2])
        else raise UnknownKeyType, "Unknown key type #{map[1]}"
        end
      end

      class EC2
        attr_reader :alg, :crv, :x, :y

        def initialize(alg:, crv:, x:, y:)
          @alg = alg
          @crv = crv
          @x = x
          @y = y
        end

        def curve_name
          row = CURVES[crv]
          row ? row[0] : ""
        end

        def field_length
          row = CURVES[crv]
          row ? row[1] : 0
        end

        def point
          "\x04".b + x.to_s.b + y.to_s.b
        end

        # The gem's `check_key` on the key a packed self attestation is made
        # with: the point is on the named curve.
        def valid_point?
          return false if curve_name.empty?
          OpenSSL::PKey::EC.from_public_bytes(curve_name, point)
          true
        rescue OpenSSL::PKey::PKeyError
          false
        end
      end

      class RSA
        attr_reader :alg, :n, :e

        def initialize(alg:, n:, e:)
          @alg = alg
          @n = n
          @e = e
        end
      end

      class OKP
        attr_reader :alg, :crv, :x

        def initialize(alg:, crv:, x:)
          @alg = alg
          @crv = crv
          @x = x
        end
      end
    end
  end

  class PublicKey
    class UnsupportedAlgorithm < Error; end

    attr_reader :cose_key

    # A stored public key: the COSE key the gem has answered since 1.12, or
    # the uncompressed P-256 point it answered before (65 bytes, 0x04 first).
    def self.deserialize(public_key)
      if public_key.bytesize == 65 && public_key.getbyte(0) == 0x04
        new(COSE::Key::EC2.new(alg: -7, crv: 1, x: public_key.byteslice(1, 32), y: public_key.byteslice(33, 32)))
      else
        new(COSE::Key.deserialize(public_key))
      end
    end

    def initialize(cose_key)
      @cose_key = cose_key
    end

    def alg
      @cose_key.alg
    end

    def verify(signature, data)
      unless COSE::Algorithm::TABLE.key?(alg)
        raise UnsupportedAlgorithm, "The public key algorithm #{alg} is not among the available COSE algorithms"
      end
      COSE::Algorithm.verify(alg, @cose_key, signature, data)
    end
  end

  class ClientData
    VALID_TOKEN_BINDING_STATUSES = ["present", "supported", "not-supported"].freeze

    def initialize(client_data_json)
      @client_data_json = client_data_json
      @data = nil
    end

    def type = data["type"]
    def origin = data["origin"]
    def token_binding = data["tokenBinding"]

    def challenge
      WebAuthn.standard_encoder.decode(data["challenge"].to_s)
    end

    def valid_token_binding_format?
      tb = token_binding
      return true unless tb
      tb.is_a?(Hash) && VALID_TOKEN_BINDING_STATUSES.include?(tb["status"])
    end

    def hash
      Digest::SHA256.digest(@client_data_json)
    end

    def data
      @data ||=
        if @client_data_json
          JSON.parse(@client_data_json)
        else
          raise ClientDataMissingError, "Client Data JSON is missing"
        end
    end
  end

  # Authenticator data (WebAuthn §6.1): the RP id hash, the flags, the sign
  # count and, when the AT flag is set, the attested credential data.
  class AuthenticatorData
    RP_ID_HASH_LENGTH = 32
    BASE_LENGTH = 37

    Credential = Struct.new(:id, :public_key, :algorithm, keyword_init: true)

    attr_reader :data, :rp_id_hash, :flags, :sign_count

    def self.deserialize(bytes)
      raise AuthenticatorDataFormatError if bytes.nil? || bytes.bytesize < BASE_LENGTH
      new(bytes.b)
    end

    def initialize(bytes)
      @data = bytes
      @rp_id_hash = bytes.byteslice(0, RP_ID_HASH_LENGTH)
      @flags = bytes.getbyte(32)
      @sign_count = bytes.byteslice(33, 4).unpack1("N")
      @attested = nil
    end

    def user_present? = (flags & 0x01) != 0
    def user_verified? = (flags & 0x04) != 0
    def credential_backup_eligible? = (flags & 0x08) != 0
    def credential_backed_up? = (flags & 0x10) != 0
    def attested_credential_data_included? = (flags & 0x40) != 0
    def extension_data_included? = (flags & 0x80) != 0
    def user_flagged? = user_present? || user_verified?

    def trailing_bytes
      @data.byteslice(BASE_LENGTH, @data.bytesize - BASE_LENGTH)
    end

    def attested_credential_data
      @attested ||= AttestedCredentialData.deserialize(trailing_bytes)
    rescue AttestedCredentialDataFormatError, CBOR::MalformedFormatError
      raise AuthenticatorDataFormatError
    end

    def credential
      attested_credential_data.credential if attested_credential_data_included?
    end

    def raw_extension_data
      return nil unless extension_data_included?
      if attested_credential_data_included?
        len = attested_credential_data.length
        trailing_bytes.byteslice(len, trailing_bytes.bytesize - len)
      else
        trailing_bytes
      end
    end

    def extension_data
      CBOR.decode(raw_extension_data)
    end

    def valid?
      (!attested_credential_data_included? || attested_credential_data.valid?) &&
        (!extension_data_included? || extension_data) &&
        @data.bytesize == BASE_LENGTH + attested_length + extension_length
    end

    def aaguid
      raw = attested_credential_data.raw_aaguid
      raw == AttestedCredentialData::ZEROED_AAGUID ? nil : attested_credential_data.aaguid
    end

    private

    def attested_length
      attested_credential_data_included? ? attested_credential_data.length.to_i : 0
    end

    def extension_length
      extension_data_included? ? raw_extension_data.bytesize : 0
    end
  end

  class AttestedCredentialData
    AAGUID_LENGTH = 16
    ZEROED_AAGUID = ("\x00" * AAGUID_LENGTH).b

    attr_reader :raw_aaguid, :id, :public_key

    def self.deserialize(bytes)
      raise AttestedCredentialDataFormatError if bytes.bytesize < AAGUID_LENGTH + 2
      new(bytes)
    end

    def initialize(bytes)
      @raw_aaguid = bytes.byteslice(0, AAGUID_LENGTH)
      id_length = bytes.byteslice(AAGUID_LENGTH, 2).unpack1("n")
      raise AttestedCredentialDataFormatError if bytes.bytesize < AAGUID_LENGTH + 2 + id_length
      @id = bytes.byteslice(AAGUID_LENGTH + 2, id_length)
      rest = bytes.byteslice(AAGUID_LENGTH + 2 + id_length, bytes.bytesize - AAGUID_LENGTH - 2 - id_length)
      decoded = CBOR.decode_with_length(rest)
      @cose_map = decoded[0]
      @public_key_length = decoded[1]
      @public_key = rest.byteslice(0, @public_key_length)
      @id_length = id_length
    end

    def aaguid
      @raw_aaguid.unpack("H8H4H4H4H12").join("-")
    end

    def cose_key
      COSE::Key.from_map(@cose_map)
    end

    def valid?
      @cose_map.is_a?(Hash) && !@cose_map[3].nil?
    end

    def algorithm
      COSE::Algorithm.name_of(@cose_map[3])
    end

    def credential
      AuthenticatorData::Credential.new(id: id, public_key: public_key, algorithm: algorithm) if valid?
    end

    def length
      AAGUID_LENGTH + 2 + @id_length + @public_key_length if valid?
    end
  end

  module AttestationStatement
    class FormatNotSupportedError < Error; end
    class UnsupportedAlgorithm < Error; end

    ATTESTATION_TYPE_NONE = "None"
    ATTESTATION_TYPE_SELF = "Self"
    ATTESTATION_TYPE_BASIC_OR_ATTCA = "Basic_or_AttCA"
    FORMATS = ["none", "fido-u2f", "packed", "android-safetynet", "android-key", "tpm", "apple"].freeze

    def self.from(format, statement, relying_party)
      raise FormatNotSupportedError, "Unsupported attestation format '#{format}'" unless FORMATS.include?(format)
      Statement.new(format, statement, relying_party)
    end

    class Statement
      attr_reader :format, :statement

      def initialize(format, statement, relying_party)
        @format = format
        @statement = statement
        @relying_party = relying_party
      end

      # [attestation type, trust path] when it verifies, false otherwise.
      def valid?(authenticator_data, client_data_hash)
        case format
        when "none"
          if statement.is_a?(Hash) && statement.empty? && acceptable?(ATTESTATION_TYPE_NONE)
            [ATTESTATION_TYPE_NONE, nil]
          else
            false
          end
        when "packed"
          valid_packed?(authenticator_data, client_data_hash)
        else
          # needs the format's certificate chain checked against roots
          false
        end
      end

      private

      def acceptable?(type)
        @relying_party.acceptable_attestation_types.include?(type)
      end

      def valid_packed?(authenticator_data, client_data_hash)
        return false unless statement.is_a?(Hash)
        alg = statement["alg"]
        sig = statement["sig"]
        return false unless alg && sig
        # with x5c: Basic or AttCA, which only a root certificate can vouch for
        return false if statement["x5c"]
        unless COSE::Algorithm::TABLE.key?(alg) && @relying_party.algorithms.include?(COSE::Algorithm.name_of(alg))
          raise UnsupportedAlgorithm, "Unsupported algorithm #{alg}"
        end
        key = authenticator_data.attested_credential_data.cose_key
        return false unless alg == key.alg
        return false if key.is_a?(COSE::Key::EC2) && !key.valid_point?
        signed = authenticator_data.data + client_data_hash
        return false unless COSE::Algorithm.verify(alg, key, sig, signed)
        return false unless acceptable?(ATTESTATION_TYPE_SELF)
        [ATTESTATION_TYPE_SELF, nil]
      end
    end
  end

  class AttestationObject
    attr_reader :authenticator_data, :attestation_statement

    def self.deserialize(bytes, relying_party)
      map = CBOR.decode(bytes)
      new(AuthenticatorData.deserialize(map["authData"]),
          AttestationStatement.from(map["fmt"], map["attStmt"], relying_party))
    end

    def initialize(authenticator_data, attestation_statement)
      @authenticator_data = authenticator_data
      @attestation_statement = attestation_statement
    end

    def valid_attested_credential?
      authenticator_data.attested_credential_data_included? && authenticator_data.attested_credential_data.valid?
    end
  end

  # The checks both ceremonies make, in the gem's order, each raising the
  # error the gem raises for it.
  class AuthenticatorResponse
    attr_reader :relying_party

    def initialize(client_data_json, relying_party)
      @client_data_json = client_data_json
      @relying_party = relying_party
      @client_data = nil
    end

    def client_data
      @client_data ||= ClientData.new(@client_data_json)
    end

    def verify_common(expected_challenge, user_presence, user_verification, rp_id)
      expected_origin = relying_party.allowed_origins || raise("Unspecified expected origin")
      rp_id ||= relying_party.id

      raise TypeVerificationError unless client_data.type == type
      raise TokenBindingVerificationError unless client_data.valid_token_binding_format?
      raise ChallengeVerificationError unless WebAuthn.secure_compare(client_data.challenge, expected_challenge)
      raise OriginVerificationError unless expected_origin.include?(client_data.origin)
      raise AuthenticatorDataVerificationError unless authenticator_data_valid?
      rp_id ||= (expected_origin.size == 1 ? URI(expected_origin.first).host : nil)
      raise RpIdVerificationError unless rp_id && Digest::SHA256.digest(rp_id) == authenticator_data.rp_id_hash
      if (user_presence.nil? && !relying_party.silent_authentication) || user_presence
        raise UserPresenceVerificationError unless authenticator_data.user_flagged?
      end
      if user_verification
        raise UserVerifiedVerificationError unless authenticator_data.user_verified?
      end
      true
    end

    private

    def authenticator_data_valid?
      authenticator_data.valid?
    rescue AuthenticatorDataFormatError
      false
    end
  end

  class AuthenticatorAttestationResponse < AuthenticatorResponse
    attr_reader :transports, :attestation_type

    def self.from_client(response, relying_party)
      encoder = relying_party.encoder
      new(encoder.decode(response["attestationObject"]), response["transports"],
          encoder.decode(response["clientDataJSON"]), relying_party)
    end

    def initialize(attestation_object_bytes, transports, client_data_json, relying_party)
      super(client_data_json, relying_party)
      @attestation_object_bytes = attestation_object_bytes
      @transports = transports
      @attestation_object = nil
      @attestation_type = nil
    end

    def attestation_object
      @attestation_object ||= AttestationObject.deserialize(@attestation_object_bytes, relying_party)
    end

    def authenticator_data
      attestation_object.authenticator_data
    end

    def type
      TYPES[:create]
    end

    def verify(expected_challenge, user_presence, user_verification)
      verify_common(expected_challenge, user_presence, user_verification, nil)
      unless attestation_object.valid_attested_credential? &&
             relying_party.algorithms.include?(authenticator_data.credential.algorithm)
        raise AttestedCredentialVerificationError
      end
      if relying_party.verify_attestation_statement
        result = attestation_object.attestation_statement.valid?(authenticator_data, client_data.hash)
        raise AttestationStatementVerificationError unless result
        @attestation_type = result[0]
      end
      true
    end
  end

  class AuthenticatorAssertionResponse < AuthenticatorResponse
    attr_reader :user_handle

    def self.from_client(response, relying_party)
      encoder = relying_party.encoder
      handle = response["userHandle"]
      new(encoder.decode(response["authenticatorData"]), encoder.decode(response["clientDataJSON"]),
          encoder.decode(response["signature"]), handle ? encoder.decode(handle) : nil, relying_party)
    end

    def initialize(authenticator_data_bytes, client_data_json, signature, user_handle, relying_party)
      super(client_data_json, relying_party)
      @authenticator_data_bytes = authenticator_data_bytes
      @signature = signature
      @user_handle = user_handle
      @authenticator_data = nil
    end

    def authenticator_data
      @authenticator_data ||= AuthenticatorData.deserialize(@authenticator_data_bytes)
    end

    def type
      TYPES[:get]
    end

    def verify(expected_challenge, public_key, sign_count, user_presence, user_verification)
      verify_common(expected_challenge, user_presence, user_verification, nil)
      raise SignatureVerificationError unless PublicKey.deserialize(public_key).verify(@signature, @authenticator_data_bytes + client_data.hash)
      stored = sign_count || 0
      if authenticator_data.sign_count != 0 || stored != 0
        raise SignCountVerificationError unless authenticator_data.sign_count > stored
      end
      true
    end
  end

  class PublicKeyCredentialWithAttestation < PublicKeyCredential
    def self.from_client(credential, relying_party: WebAuthn.configuration.relying_party)
      new(
        type: credential["type"],
        id: credential["id"],
        raw_id: relying_party.encoder.decode(credential["rawId"]),
        client_extension_outputs: credential["clientExtensionResults"],
        authenticator_attachment: credential["authenticatorAttachment"],
        response: AuthenticatorAttestationResponse.from_client(credential["response"], relying_party),
        relying_party: relying_party
      )
    end

    def verify(challenge, user_presence: nil, user_verification: nil)
      verify_credential(challenge)
      response.verify(encoder.decode(challenge), user_presence, user_verification)
      true
    end

    def sign_count
      response.authenticator_data.sign_count
    end

    def raw_public_key
      cred = response.authenticator_data.credential
      cred ? cred.public_key : nil
    end

    def public_key
      raw = raw_public_key
      raw ? encoder.encode(raw) : nil
    end

    def backup_eligible? = response.authenticator_data.credential_backup_eligible?
    def backed_up? = response.authenticator_data.credential_backed_up?
  end

  class PublicKeyCredentialWithAssertion < PublicKeyCredential
    def self.from_client(credential, relying_party: WebAuthn.configuration.relying_party)
      new(
        type: credential["type"],
        id: credential["id"],
        raw_id: relying_party.encoder.decode(credential["rawId"]),
        client_extension_outputs: credential["clientExtensionResults"],
        authenticator_attachment: credential["authenticatorAttachment"],
        response: AuthenticatorAssertionResponse.from_client(credential["response"], relying_party),
        relying_party: relying_party
      )
    end

    def verify(challenge, public_key:, sign_count:, user_presence: nil, user_verification: nil)
      verify_credential(challenge)
      response.verify(encoder.decode(challenge), encoder.decode(public_key), sign_count, user_presence, user_verification)
      true
    end

    def sign_count
      response.authenticator_data.sign_count
    end

    def raw_user_handle
      response.user_handle
    end

    def user_handle
      raw = raw_user_handle
      raw ? encoder.encode(raw) : nil
    end

    def backup_eligible? = response.authenticator_data.credential_backup_eligible?
    def backed_up? = response.authenticator_data.credential_backed_up?
  end
end
