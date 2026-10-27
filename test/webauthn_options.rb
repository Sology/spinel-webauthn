require "webauthn"

WebAuthn.configure do |config|
  config.allowed_origins = ["https://example.com"]
  config.rp_name = "Example"
  config.rp_id = "example.com"
end

def attempt(label)
  result = yield
  puts "#{label}: #{result.inspect}"
rescue WebAuthn::Error => e
  puts "#{label}: #{e.class}: #{e.message}"
rescue RuntimeError => e
  puts "#{label}: #{e.class}: #{e.message}"
end

create = WebAuthn::Credential.options_for_create(
  user: { id: "dXNlci1oYW5kbGU", name: "alice", display_name: "Alice" },
  exclude: ["7dFg2jJxEQmVk2CQLKFqpg", "kM0AlsHYhuJbjn2Z4SmCHQ"],
  authenticator_selection: { user_verification: "preferred", resident_key: "preferred" }
)
puts create.challenge.length
json = create.as_json
puts json[:challenge] == create.challenge
json.delete(:challenge)
p json
Array(json[:excludeCredentials]).each { |entry| entry[:transports] = ["hybrid", "internal"] }
puts JSON.generate(json)

get = WebAuthn::Credential.options_for_get(allow: ["7dFg2jJxEQmVk2CQLKFqpg"], user_verification: "preferred")
gj = get.as_json
puts gj[:challenge] == get.challenge
gj.delete(:challenge)
p gj
puts JSON.generate(gj.merge(hints: ["client-device"]))
p WebAuthn::Credential.options_for_get(allow: [], user_verification: "preferred").as_json.reject { |k, _| k == :challenge }

id = WebAuthn.generate_user_id
puts id.length
puts WebAuthn.configuration.encoder.decode(id).bytesize
