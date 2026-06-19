#include <iostream>
#include <fstream>
#include <string>
#include <sodium.h>

// Registers a new account: prompts for a password, hashes it with libsodium's
// password-hashing API (Argon2id under the hood), and writes the resulting
// hash string to Creds.txt. crypto_pwhash_str() embeds the algorithm,
// opslimit, memlimit, and salt directly in the output string, so no extra
// metadata needs to be stored alongside it for later verification.
void create() {
	std::string pass;
	std::cout << "Enter Credentials: ";
	std::cin >> pass;

	char hashed[crypto_pwhash_STRBYTES];
	if (crypto_pwhash_str(hashed, pass.c_str(), pass.size(),
		crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
		// This only fails if the system can't allocate the memory the
		// requested OPSLIMIT/MEMLIMIT combination needs.
		std::cout << "Out of memory during hashing process";
		return;
	}

	std::ofstream outfile("Creds.txt");
	if (outfile.is_open()) {
		outfile << hashed;
		outfile.close();
	}
}

// Logs an existing account in: prompts for a password attempt, reads the
// stored hash from Creds.txt, and asks crypto_pwhash_str_verify() to check
// the attempt against it. Verification re-derives the hash using the
// parameters embedded in storedhash and does a constant-time comparison, so
// none of the original opslimit/memlimit/salt values need to be tracked here.
void read() {
	std::string enteredpass;
	std::cout << "Enter Credentials: \n";
	std::cin >> enteredpass;

	std::ifstream infile("Creds.txt");
	if (!infile.is_open()) {
		std::cout << "Credentials not found\n";
		return;
	}

	std::string storedhash;
	getline(infile, storedhash);

	if (crypto_pwhash_str_verify(storedhash.c_str(), enteredpass.c_str(), enteredpass.size()) == 0) {
		std::cout << "Entered program";
	}
	else {
		std::cout << "Incorrect credentials. failed to enter program";
	}
}

int main() {
	// sodium_init() must succeed before any other libsodium call is made;
	// bail out immediately rather than falling through to hashing calls
	// against an uninitialized library.
	if (sodium_init() < 0) {
		std::cout << "libsodium init failure";
		return 1;
	}

	int choice;

	std::cout << "[1] Register account\n";
	std::cout << "[2] Login\n";
	std::cin >> choice;

	if (choice == 1) {
		create();
	}
	else if (choice == 2) {
		read();
	}
	else {
		std::cout << "Invalid choice detected. Program exiting";
	}
}
