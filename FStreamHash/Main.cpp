// std::getenv trips MSVC's "unsafe function" deprecation; it's used here only
// for optional config paths, so silence the warning rather than switching to
// the non-portable _dupenv_s.
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <limits>
#include <cstdlib>
#include <sodium.h>


// ---------------------------------------------------------------------------
// Configuration / paths
// ---------------------------------------------------------------------------

// Both paths are overridable via environment variables so the program isn't
// tied to whatever directory it happens to run from. Falls back to filenames
// in the working directory when the variables aren't set.
static const char* creds_path() {
	const char* p = std::getenv("FSTREAMHASH_CREDS");
	return (p && *p) ? p : "Creds.txt";
}

static const char* pepper_path() {
	const char* p = std::getenv("FSTREAMHASH_PEPPER");
	return (p && *p) ? p : "pepper.key";
}


// ---------------------------------------------------------------------------
// Pepper (keyed-hash key)
// ---------------------------------------------------------------------------

// Loads the 32-byte pepper key used to derive username lookup hashes. On first
// run the key file won't exist, so we generate a fresh random key and persist
// it. The pepper makes the username digests deterministic (so we can search by
// username) while keeping plaintext usernames out of the creds file.
//
// NOTE: this is not secret-grade protection. Anyone holding both pepper.key and
// Creds.txt can run a dictionary attack to recover usernames. The pepper just
// raises the bar above storing usernames in the clear.
static bool load_or_create_pepper(unsigned char key[crypto_generichash_KEYBYTES]) {
	std::ifstream in(pepper_path(), std::ios::binary);
	if (in.is_open()) {
		in.read(reinterpret_cast<char*>(key), crypto_generichash_KEYBYTES);
		if (in.gcount() == crypto_generichash_KEYBYTES) {
			return true;
		}
		// File exists but is the wrong size / truncated: refuse rather than
		// silently regenerating, which would orphan every existing record.
		std::cout << "Pepper key file is corrupt; refusing to continue.\n";
		return false;
	}

	randombytes_buf(key, crypto_generichash_KEYBYTES);
	std::ofstream out(pepper_path(), std::ios::binary | std::ios::trunc);
	if (!out.is_open()) {
		std::cout << "Could not create pepper key file.\n";
		return false;
	}
	out.write(reinterpret_cast<const char*>(key), crypto_generichash_KEYBYTES);
	return out.good();
}

// Derives the searchable lookup token for a username: keyed BLAKE2b over the
// username, hex-encoded. Same username + same key always yields the same hex,
// which is what lets us find a user's record without storing the name.
static std::string lookup_hash(const std::string& user,
	const unsigned char key[crypto_generichash_KEYBYTES]) {
	unsigned char digest[crypto_generichash_BYTES];
	crypto_generichash(digest, sizeof digest,
		reinterpret_cast<const unsigned char*>(user.c_str()), user.size(),
		key, crypto_generichash_KEYBYTES);

	char hex[sizeof(digest) * 2 + 1];
	sodium_bin2hex(hex, sizeof hex, digest, sizeof digest);
	return std::string(hex);
}


// ---------------------------------------------------------------------------
// Record storage
// ---------------------------------------------------------------------------

// One account per line in Creds.txt: "<username_lookup_hex>:<argon2_pw_hash>".
// ':' is a safe delimiter because Argon2 encoded strings only use '$', base64
// (A-Za-z0-9+/), ',' and '=' and the hex digest is purely [0-9a-f].
struct Record {
	std::string userHex;
	std::string pwHash;
};

static std::vector<Record> load_records() {
	std::vector<Record> records;
	std::ifstream in(creds_path());
	if (!in.is_open()) {
		// Missing file just means no accounts yet, not an error.
		return records;
	}

	std::string line;
	while (std::getline(in, line)) {
		if (line.empty()) {
			continue;
		}
		std::string::size_type sep = line.find(':');
		if (sep == std::string::npos) {
			continue; // skip malformed lines defensively
		}
		Record r;
		r.userHex = line.substr(0, sep);
		r.pwHash = line.substr(sep + 1);
		records.push_back(r);
	}
	return records;
}

static bool save_records(const std::vector<Record>& records) {
	std::ofstream out(creds_path(), std::ios::trunc);
	if (!out.is_open()) {
		std::cout << "Could not open credentials file for writing.\n";
		return false;
	}
	for (const Record& r : records) {
		out << r.userHex << ':' << r.pwHash << '\n';
	}
	if (!out.good()) {
		std::cout << "Failed while writing credentials file.\n";
		return false;
	}
	return true;
}

// Returns the index of the record matching userHex, or -1 if not found.
static int find_record(const std::vector<Record>& records, const std::string& userHex) {
	for (std::size_t i = 0; i < records.size(); ++i) {
		if (records[i].userHex == userHex) {
			return static_cast<int>(i);
		}
	}
	return -1;
}


// ---------------------------------------------------------------------------
// Account actions
// ---------------------------------------------------------------------------

// Registers a new account: prompts for a username + password, rejects the
// username if it already exists, hashes the password with libsodium's
// Argon2id, and appends the record. crypto_pwhash_str() embeds the algorithm,
// opslimit, memlimit, and salt directly in the output, so the stored hash is
// fully self-describing for later verification.
static void create(const unsigned char key[crypto_generichash_KEYBYTES]) {
	std::string user, pass;
	std::cout << "Enter Username : \n";
	std::cin >> user;
	std::cout << "Enter Password : \n";
	std::cin >> pass;

	std::string userHex = lookup_hash(user, key);
	std::vector<Record> records = load_records();
	if (find_record(records, userHex) != -1) {
		std::cout << "Username taken.\n";
		return;
	}

	char hashed[crypto_pwhash_STRBYTES];
	if (crypto_pwhash_str(hashed, pass.c_str(), pass.size(),
		crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
		// Only fails if the system can't allocate the memory the requested
		// OPSLIMIT/MEMLIMIT combination needs.
		std::cout << "Out of memory during hashing process.\n";
		return;
	}

	Record r;
	r.userHex = userHex;
	r.pwHash = hashed;
	records.push_back(r);

	if (save_records(records)) {
		std::cout << "Account registered.\n";
	}
}

// Logs an existing account in: derives the username lookup hash, finds the
// matching record, and verifies the password against the stored Argon2id hash.
// The failure message is identical whether the username is unknown or the
// password is wrong, so it doesn't leak which usernames exist.
static void read(const unsigned char key[crypto_generichash_KEYBYTES]) {
	std::string user, pass;
	std::cout << "Enter Username : \n";
	std::cin >> user;
	std::cout << "Enter Password : \n";
	std::cin >> pass;

	std::vector<Record> records = load_records();
	int idx = find_record(records, lookup_hash(user, key));

	if (idx != -1 &&
		crypto_pwhash_str_verify(records[idx].pwHash.c_str(), pass.c_str(), pass.size()) == 0) {
		std::cout << "Entered program.\n";
	}
	else {
		std::cout << "Incorrect credentials. Failed to enter program.\n";
	}
}

// Changes an existing account's password after verifying the current one.
static void change_password(const unsigned char key[crypto_generichash_KEYBYTES]) {
	std::string user, oldpass, newpass;
	std::cout << "Enter Username : \n";
	std::cin >> user;
	std::cout << "Enter current Password : \n";
	std::cin >> oldpass;

	std::vector<Record> records = load_records();
	int idx = find_record(records, lookup_hash(user, key));
	if (idx == -1 ||
		crypto_pwhash_str_verify(records[idx].pwHash.c_str(), oldpass.c_str(), oldpass.size()) != 0) {
		std::cout << "Incorrect credentials.\n";
		return;
	}

	std::cout << "Enter new Password : \n";
	std::cin >> newpass;

	char hashed[crypto_pwhash_STRBYTES];
	if (crypto_pwhash_str(hashed, newpass.c_str(), newpass.size(),
		crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
		std::cout << "Out of memory during hashing process.\n";
		return;
	}

	records[idx].pwHash = hashed;
	if (save_records(records)) {
		std::cout << "Password changed.\n";
	}
}

// Deletes an account after verifying its password.
static void delete_account(const unsigned char key[crypto_generichash_KEYBYTES]) {
	std::string user, pass;
	std::cout << "Enter Username : \n";
	std::cin >> user;
	std::cout << "Enter Password : \n";
	std::cin >> pass;

	std::vector<Record> records = load_records();
	int idx = find_record(records, lookup_hash(user, key));
	if (idx == -1 ||
		crypto_pwhash_str_verify(records[idx].pwHash.c_str(), pass.c_str(), pass.size()) != 0) {
		std::cout << "Incorrect credentials.\n";
		return;
	}

	records.erase(records.begin() + idx);
	if (save_records(records)) {
		std::cout << "Account deleted.\n";
	}
}


// ---------------------------------------------------------------------------
// Menu loop
// ---------------------------------------------------------------------------

int main() {
	// sodium_init() must succeed before any other libsodium call; bail out
	// rather than running hashing calls against an uninitialized library.
	if (sodium_init() < 0) {
		std::cout << "libsodium init failure\n";
		return 1;
	}

	unsigned char key[crypto_generichash_KEYBYTES];
	if (!load_or_create_pepper(key)) {
		return 1;
	}

	while (true) {
		std::cout << "\n[1] Register account\n";
		std::cout << "[2] Login\n";
		std::cout << "[3] Change password\n";
		std::cout << "[4] Delete account\n";
		std::cout << "[5] Exit\n";

		int choice;
		if (!(std::cin >> choice)) {
			// Non-numeric input would otherwise leave cin in a failed state
			// and spin the loop forever; clear the error and discard the line.
			std::cin.clear();
			std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			std::cout << "Invalid input. Please enter a number.\n";
			continue;
		}

		switch (choice) {
		case 1: create(key); break;
		case 2: read(key); break;
		case 3: change_password(key); break;
		case 4: delete_account(key); break;
		case 5: std::cout << "Goodbye.\n"; return 0;
		default: std::cout << "Invalid choice.\n"; break;
		}
	}
}
