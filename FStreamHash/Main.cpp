#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <limits>
#include <cstdlib>
#include <sodium.h>


static const char* creds_path() {
	const char* p = std::getenv("FSTREAMHASH_CREDS");
	return (p && *p) ? p : "Creds.txt";
}

static const char* pepper_path() {
	const char* p = std::getenv("FSTREAMHASH_PEPPER");
	return (p && *p) ? p : "pepper.key";
}


static bool load_or_create_pepper(unsigned char key[crypto_generichash_KEYBYTES]) {
	std::ifstream in(pepper_path(), std::ios::binary);
	if (in.is_open()) {
		in.read(reinterpret_cast<char*>(key), crypto_generichash_KEYBYTES);
		if (in.gcount() == crypto_generichash_KEYBYTES) {
			return true;
		}
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


struct Record {
	std::string userHex;
	std::string pwHash;
};

static std::vector<Record> load_records() {
	std::vector<Record> records;
	std::ifstream in(creds_path());
	if (!in.is_open()) {
		return records;
	}

	std::string line;
	while (std::getline(in, line)) {
		if (line.empty()) {
			continue;
		}
		std::string::size_type sep = line.find(':');
		if (sep == std::string::npos) {
			continue;
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

static int find_record(const std::vector<Record>& records, const std::string& userHex) {
	for (std::size_t i = 0; i < records.size(); ++i) {
		if (records[i].userHex == userHex) {
			return static_cast<int>(i);
		}
	}
	return -1;
}


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


int main() {
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
