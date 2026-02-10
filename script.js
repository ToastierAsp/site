let sessionPassphrase = null;
// removed public IP / obfuscated site-pass logic per request
let publicIP = '';

function bufToBase64(buf){
	return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuf(b64){
	const str = atob(b64);
	const arr = new Uint8Array(str.length);
	for(let i=0;i<str.length;i++) arr[i]=str.charCodeAt(i);
	return arr.buffer;
}

async function deriveKey(passphrase, salt, iterations=200000){
	const enc = new TextEncoder();
	const baseKey = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
	return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations,hash:'SHA-256'}, baseKey, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']);
}

async function encryptMessage(passphrase, text){
	const enc = new TextEncoder();
	const salt = crypto.getRandomValues(new Uint8Array(16));
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const key = await deriveKey(passphrase, salt.buffer);
	const ct = await crypto.subtle.encrypt({name:'AES-GCM',iv}, key, enc.encode(text));
	// package: salt + iv + ciphertext, base64
	const joined = new Uint8Array(salt.byteLength + iv.byteLength + ct.byteLength);
	joined.set(salt,0); joined.set(iv,salt.byteLength); joined.set(new Uint8Array(ct), salt.byteLength+iv.byteLength);
	return bufToBase64(joined.buffer);
}

async function decryptMessage(passphrase, blobB64){
	try{
		const buf = base64ToBuf(blobB64);
		const arr = new Uint8Array(buf);
		if(arr.length < 28) throw new Error('Blob too short');
		const salt = arr.slice(0,16).buffer;
		const iv = arr.slice(16,28).buffer;
		const ct = arr.slice(28).buffer;
		const key = await deriveKey(passphrase, salt);
		const ptBuf = await crypto.subtle.decrypt({name:'AES-GCM',iv}, key, ct);
		return new TextDecoder().decode(ptBuf);
	}catch(e){
		throw new Error('Decryption failed: '+e.message);
	}
}

// functions removed: message-based passphrase generation and key combination

async function fetchPublicIP(){
	try{
		const res = await fetch('https://api.ipify.org?format=json');
		if(!res.ok) throw new Error('ipify failed');
		const j = await res.json();
		return j.ip || '';
	}catch(e){
		try{
			const res2 = await fetch('https://ifconfig.co/json');
			if(!res2.ok) throw new Error('ifconfig failed');
			const j2 = await res2.json();
			return j2.ip || j2.ipv4 || '';
		}catch(_){
			return '';
		}
	}
}

async function hashIP(ip){
	if(!ip) return '';
	const enc = new TextEncoder();
	const digest = await crypto.subtle.digest('SHA-256', enc.encode(ip));
	// convert to hex string
	let hex = '';
	const view = new Uint8Array(digest);
	for(let i=0; i<view.length; i++){
		hex += ('0' + view[i].toString(16)).slice(-2);
	}
	return hex;
}

// functions removed: IP fetch and obfuscation

// UI wiring
document.addEventListener('DOMContentLoaded', ()=>{
	console.debug('scripts.js: DOMContentLoaded');
	const app = document.getElementById('app');
	const globalPasskeyEl = document.getElementById('globalPasskey');
	const passkeyBanner = document.getElementById('passkeyBanner');
	const copyGlobalBtn = document.getElementById('copyGlobalPass');

 	const plaintext = document.getElementById('plaintext');
	const encryptBtn = document.getElementById('encryptBtn');
	const ciphertext = document.getElementById('ciphertext');
	const copyCipher = document.getElementById('copyCipher');
	const recipientPasskey = document.getElementById('recipientPasskey');

	// fetch public IP, hash it, and show as encrypted passkey if no generated passkey yet
	(async ()=>{
		console.debug('scripts.js: initializing passkey');
		try{
				const ip = await fetchPublicIP();
				publicIP = ip || '';
				if(!publicIP){
					console.warn('scripts.js: public IP unavailable — passkey disabled (no fallback)');
					if(globalPasskeyEl) globalPasskeyEl.textContent = 'PASSKEY UNAVAILABLE';
					const yki = document.getElementById('yourKeyInput');
					if(yki) yki.value = '';
					if(passkeyBanner){
						passkeyBanner.classList.remove('hidden');
						passkeyBanner.style.display = 'flex';
					}
					return;
				}
				const hashed = await hashIP(publicIP);
				console.debug('scripts.js: passkey hashed', (hashed || '').slice(0,8));
				if(globalPasskeyEl) globalPasskeyEl.textContent = hashed;
				const yki = document.getElementById('yourKeyInput');
				if(yki) yki.value = hashed;
				if(passkeyBanner){
					passkeyBanner.classList.remove('hidden');
					passkeyBanner.style.display = 'flex';
					console.debug('scripts.js: passkeyBanner shown');
				}
		}catch(err){
				console.error('passkey init failed', err);
				if(globalPasskeyEl) globalPasskeyEl.textContent = 'PASSKEY UNAVAILABLE';
				const yki = document.getElementById('yourKeyInput');
				if(yki) yki.value = '';
				if(passkeyBanner){ passkeyBanner.classList.remove('hidden'); passkeyBanner.style.display='flex'; }
		}
	})();

	if(copyGlobalBtn){
		copyGlobalBtn.addEventListener('click', async ()=>{
			const val = (globalPasskeyEl && globalPasskeyEl.textContent) || '';
			if(val){ await navigator.clipboard.writeText(val); alert('Passkey copied'); }
		});
	}

	const ciphertextInput = document.getElementById('ciphertextInput');
	const decryptBtn = document.getElementById('decryptBtn');
	const decrypted = document.getElementById('decrypted');
	const yourKeyInput = document.getElementById('yourKeyInput');


	// Removed End Session button and its handler — session clearing is manual now

	encryptBtn.addEventListener('click', async ()=>{
		try{
			// use the recipient's passkey to encrypt (so they can decrypt with their auto-filled key)
			const recPass = (recipientPasskey && recipientPasskey.value.trim()) || '';
			if(!recPass){ alert('Enter recipient\'s passkey to encrypt.'); return; }
			const ct = await encryptMessage(recPass, plaintext.value);
			ciphertext.value = ct;
		}catch(e){ alert('Encrypt error: '+e.message); }
	});

	copyCipher.addEventListener('click', async ()=>{
		if(!ciphertext.value) return;
		await navigator.clipboard.writeText(ciphertext.value);
		alert('Copied');
	});

	decryptBtn.addEventListener('click', async ()=>{
		// decrypt requires the passkey
		const passkey = (yourKeyInput && yourKeyInput.value.trim()) || '';
		if(!passkey){ alert('Passkey not set.'); return; }
		try{
			const pt = await decryptMessage(passkey, ciphertextInput.value.trim());
			decrypted.value = pt;
		}catch(e){
			decrypted.value = 'Decryption failed: wrong passkey or corrupted data.';
		}
	});

	// no IP-based key behavior; when encryption generates a passphrase we'll display it
});
