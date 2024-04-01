let encryptionData;

function encryptAndHash() {
  const input = document.getElementById("input");
  const data = input.value;
  const key = CryptoJS.lib.WordArray.random(128 / 8);

  const encrypted = CryptoJS.AES.encrypt(data, key, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7,
  });

  const hashed = CryptoJS.MD5(encrypted.ciphertext);

  document.getElementById("encrypted").textContent = encrypted.ciphertext.toString();
  document.getElementById("hashed").textContent = hashed.toString();

  encryptionData = { key: key, encrypted: encrypted, hashed: hashed };
}

function setCiphertextAndDecryptAndVerify() {
  const inputCiphertext = document.getElementById("ciphertext");
  const ciphertext = inputCiphertext.value;

  const inputHash = document.getElementById("inputHash");
  const userInputHash = inputHash.value;

  // Update the encrypted and hashed HTML elements with the input ciphertext and hash
  document.getElementById("encrypted").textContent = ciphertext;
  document.getElementById("hashed").textContent = userInputHash;

  // Call the decryptAndVerify function
  decryptAndVerify(userInputHash);
}

function decryptAndVerify(userInputHash) {
  const encryptedCiphertext = CryptoJS.enc.Hex.parse(document.getElementById("encrypted").textContent);

  const decrypted = CryptoJS.AES.decrypt(
    { ciphertext: encryptedCiphertext },
    encryptionData.key,
    { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }
  );

  const verifiedHashed = CryptoJS.MD5(encryptedCiphertext);

  const isVerified = userInputHash === verifiedHashed.toString();

  document.getElementById("decrypted").textContent = decrypted.toString(CryptoJS.enc.Utf8);
  document.getElementById("verification").textContent = isVerified ? "Verified" : "Not Verified";
}