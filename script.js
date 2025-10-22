// Fixed key for AES encryption (in a real app, use secure key management)
const key = 'mySecretKey12345'; // 16 bytes for AES-128

document.getElementById('encryptBtn').addEventListener('click', function() {
    const message = document.getElementById('senderInput').value;
    if (message.trim() === '') {
        alert('Please enter a message to encrypt.');
        return;
    }
    const encrypted = CryptoJS.AES.encrypt(message, key).toString();
    document.getElementById('encryptedOutput').innerText = 'Encrypted: ' + encrypted;
});

document.getElementById('decryptBtn').addEventListener('click', function() {
    const encryptedMessage = document.getElementById('receiverInput').value;
    if (encryptedMessage.trim() === '') {
        alert('Please enter an encrypted message to decrypt.');
        return;
    }
    try {
        const decrypted = CryptoJS.AES.decrypt(encryptedMessage, key).toString(CryptoJS.enc.Utf8);
        document.getElementById('decryptedOutput').innerText = 'Decrypted: ' + decrypted;
    } catch (e) {
        alert('Invalid encrypted message.');
    }
});
