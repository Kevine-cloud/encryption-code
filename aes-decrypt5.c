#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/params.h>

#define AES_BLOCK_SIZE 16
#define KEY_SIZE 32  // For AES-256
#define MAX_BUFFER_SIZE 4096

// Structure pour les modes de chiffrement
typedef enum {
    CBC_MODE,
    GCM_MODE,
    UNKNOWN_MODE
} CipherMode;

// Déclaration de la fonction verify_etm_signature
int verify_etm_signature(const char* encrypted_file, const unsigned char* key);

// Fonction utilitaire pour gérer les erreurs OpenSSL
void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// Fonction utilitaire pour obtenir le minimum entre deux valeurs
static inline size_t MIN(size_t a, size_t b) {
    return (a < b) ? a : b;
}

// Function to decrypt a file that was encrypted with AES-256 CBC or GCM
int decrypt_file(const char* input_file, const char* output_file, const char* key_file, CipherMode mode) {
    FILE *in_file = NULL, *out_file = NULL, *key_file_ptr = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher;
    unsigned char key[KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char buffer[MAX_BUFFER_SIZE];
    unsigned char out_buffer[MAX_BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[16];  // For GCM authentication
    int in_len, out_len, final_len, ret = -1;
    long file_size;

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Read the key from file
    key_file_ptr = fopen(key_file, "rb");
    if (!key_file_ptr) {
        fprintf(stderr, "Error: Cannot open key file\n");
        goto cleanup;
    }
    if (fread(key, 1, KEY_SIZE, key_file_ptr) != KEY_SIZE) {
        fprintf(stderr, "Error: Invalid key file size\n");
        goto cleanup;
    }

    // Open input file
    in_file = fopen(input_file, "rb");
    if (!in_file) {
        fprintf(stderr, "Error: Cannot open input file\n");
        goto cleanup;
    }

    // Get file size
    fseek(in_file, 0, SEEK_END);
    file_size = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);

    // Validate minimum file size
    if (file_size < AES_BLOCK_SIZE) {
        fprintf(stderr, "Error: Input file is too small\n");
        goto cleanup;
    }

    // Read IV from the beginning of the file
    if (fread(iv, 1, AES_BLOCK_SIZE, in_file) != AES_BLOCK_SIZE) {
        fprintf(stderr, "Error: Cannot read IV from file\n");
        goto cleanup;
    }

    // Create decryption context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_openssl_error();
        goto cleanup;
    }

    // Select cipher mode
    if (mode == CBC_MODE) {
        cipher = EVP_aes_256_cbc();
    } else if (mode == GCM_MODE) {
        cipher = EVP_aes_256_gcm();
        
        // For GCM, read authentication tag from the end of the file
        if (file_size < AES_BLOCK_SIZE + 16) {
            fprintf(stderr, "Error: Input file too small for GCM mode\n");
            goto cleanup;
        }
        fseek(in_file, -16, SEEK_END);
        if (fread(tag, 1, 16, in_file) != 16) {
            fprintf(stderr, "Error: Cannot read authentication tag\n");
            goto cleanup;
        }
        fseek(in_file, AES_BLOCK_SIZE, SEEK_SET);
    } else {
        fprintf(stderr, "Error: Unsupported cipher mode\n");
        goto cleanup;
    }

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        handle_openssl_error();
        goto cleanup;
    }

    // Vérifier la signature avant de commencer le déchiffrement
    if (verify_etm_signature(input_file, key) != 0) {
        fprintf(stderr, "Erreur: La signature du fichier est invalide\n");
        fprintf(stderr, "Le fichier a peut-être été altéré\n");
        goto cleanup;
    }

    // Open output file
    out_file = fopen(output_file, "wb");
    if (!out_file) {
        fprintf(stderr, "Error: Cannot create output file\n");
        goto cleanup;
    }

    // Decrypt file content
    while ((in_len = fread(buffer, 1, mode == GCM_MODE ? 
           MIN(MAX_BUFFER_SIZE, file_size - 16 - AES_BLOCK_SIZE - ftell(in_file)) : 
           MAX_BUFFER_SIZE, in_file)) > 0) {
        
        if (EVP_DecryptUpdate(ctx, out_buffer, &out_len, buffer, in_len) != 1) {
            handle_openssl_error();
            goto cleanup;
        }

        if (out_len > 0) {
            fwrite(out_buffer, 1, out_len, out_file);
        }
    }

    // Set expected tag for GCM mode
    if (mode == GCM_MODE) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) {
            handle_openssl_error();
            goto cleanup;
        }
    }

    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, out_buffer, &final_len) != 1) {
        if (mode == GCM_MODE) {
            fprintf(stderr, "Error: Authentication failed\n");
        } else {
            handle_openssl_error();
        }
        goto cleanup;
    }

    if (final_len > 0) {
        fwrite(out_buffer, 1, final_len, out_file);
    }

    ret = 0;  // Success
    printf("File successfully decrypted in %s mode!\n", 
           mode == CBC_MODE ? "CBC" : "GCM");

cleanup:
    if (key_file_ptr) fclose(key_file_ptr);
    if (in_file) fclose(in_file);
    if (out_file) fclose(out_file);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    
    return ret;
}

// Parse le mode de chiffrement à partir de la chaîne
CipherMode parse_mode(const char* mode_str) {
    if (strcmp(mode_str, "CBC") == 0) return CBC_MODE;
    if (strcmp(mode_str, "GCM") == 0) return GCM_MODE;
    return UNKNOWN_MODE;
}

// Affiche l'usage du programme
void print_usage(const char* program_name) {
    fprintf(stderr, "Usage: %s <mode> <fichier_chiffre> <fichier_dechiffre> <fichier_cle>\n", program_name);
    fprintf(stderr, "Modes disponibles: CBC, GCM\n");
    fprintf(stderr, "Exemple: %s CBC fichier.enc fichier.txt cle.bin\n", program_name);
}

// Fonction pour vérifier la signature (Encrypt-then-MAC)
int verify_etm_signature(const char* encrypted_file, const unsigned char* key) {
    FILE *file = NULL, *sig_file = NULL;
    unsigned char buffer[4096];
    size_t bytes_read;
    unsigned char stored_hmac[EVP_MAX_MD_SIZE];
    unsigned char computed_hmac[EVP_MAX_MD_SIZE];
    size_t hmac_len;
    int ret = -1;
    char sig_filename[1024];
    
    // Construire le nom du fichier de signature
    snprintf(sig_filename, sizeof(sig_filename), "%s.sig", encrypted_file);
    printf("Vérification de la signature: %s\n", sig_filename);
    
    // Créer le contexte EVP_MAC
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        fprintf(stderr, "Erreur lors de la création du contexte MAC\n");
        return -1;
    }
    
    // Créer le contexte MAC
    EVP_MAC_CTX *mac_ctx = EVP_MAC_CTX_new(mac);
    if (!mac_ctx) {
        EVP_MAC_free(mac);
        return -1;
    }
    
    // Paramètres pour HMAC-SHA256
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_END
    };
    
    // Initialiser HMAC
    if (!EVP_MAC_init(mac_ctx, key, KEY_SIZE, params)) {
        goto cleanup;
    }
    
    // Lire et calculer le MAC du fichier chiffré
    file = fopen(encrypted_file, "rb");
    if (!file) {
        fprintf(stderr, "Erreur lors de l'ouverture du fichier chiffré\n");
        goto cleanup;
    }
    
    // Calculer le MAC sur le fichier chiffré complet
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (!EVP_MAC_update(mac_ctx, buffer, bytes_read)) {
            goto cleanup;
        }
    }
    
    // Calculer le MAC final
    if (!EVP_MAC_final(mac_ctx, computed_hmac, &hmac_len, sizeof(computed_hmac))) {
        goto cleanup;
    }
    
    // Lire la signature stockée
    sig_file = fopen(sig_filename, "rb");
    if (!sig_file) {
        fprintf(stderr, "Erreur: Fichier de signature non trouvé: %s\n", sig_filename);
        goto cleanup;
    }
    
    if (fread(stored_hmac, 1, hmac_len, sig_file) != hmac_len) {
        fprintf(stderr, "Erreur lors de la lecture de la signature\n");
        goto cleanup;
    }
    
    // Comparer les signatures de manière sécurisée
    ret = CRYPTO_memcmp(computed_hmac, stored_hmac, hmac_len) == 0 ? 0 : -1;
    
    if (ret == 0) {
        printf("Vérification de la signature réussie\n");
    } else {
        fprintf(stderr, "Échec de la vérification de la signature\n");
    }
    
cleanup:
    if (file) fclose(file);
    if (sig_file) fclose(sig_file);
    EVP_MAC_CTX_free(mac_ctx);
    EVP_MAC_free(mac);
    return ret;
}

int main(int argc, char* argv[]) {
    // Vérifier le nombre d'arguments
    if (argc != 5) {
        print_usage(argv[0]);
        return 1;
    }

    // Parser le mode de chiffrement
    CipherMode mode = parse_mode(argv[1]);
    if (mode == UNKNOWN_MODE) {
        fprintf(stderr, "Erreur: Mode de chiffrement invalide\n");
        print_usage(argv[0]);
        return 1;
    }

    // Appeler la fonction de déchiffrement
    int result = decrypt_file(argv[2], argv[3], argv[4], mode);
    
    if (result != 0) {
        fprintf(stderr, "Erreur lors du déchiffrement\n");
        return 1;
    }

    return 0;
}