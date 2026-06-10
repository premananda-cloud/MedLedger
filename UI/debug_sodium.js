import _sodium from "libsodium-wrappers-sumo";

await _sodium.ready;

console.log("Has crypto_pwhash:", typeof _sodium.crypto_pwhash);
console.log(
  "Has crypto_sign_seed_keypair:",
  typeof _sodium.crypto_sign_seed_keypair,
);
console.log(
  "Has crypto_box_seed_keypair:",
  typeof _sodium.crypto_box_seed_keypair,
);
