#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>  // Pour STDIN_FILENO
#include <termios.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#define AES_BLOCK_SIZE 16
#define KEY_SIZE 32  // Pour AES-256
#define SALT_SIZE 16
#define ITERATIONS 10000  // Nombre d'itérations pour PBKDF2

// Structure pour les modes de chiffrement
typedef enum {
    CBC_MODE,
    GCM_MODE,
    UNKNOWN_MODE
} CipherMode;

// Déclarations des fonctions de signature
int compute_signature(const char* encrypted_file, const char* original_file, const unsigned char* key);
int store_signature(const char* encrypted_file, const unsigned char* signature, unsigned int sig_len);

// Affiche une erreur OpenSSL
void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// Fonction pour lire un mot de passe de manière sécurisée
void read_password(char* password, size_t max_len) {
    struct termios old_flags, new_flags;
    
    // Désactiver l'écho des caractères
    tcgetattr(STDIN_FILENO, &old_flags);
    new_flags = old_flags;
    new_flags.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_flags);
    
    printf("Entrez le mot de passe: ");
    fgets(password, max_len, stdin);
    
    // Supprimer le retour à la ligne
    password[strcspn(password, "\n")] = 0;
    
    // Restaurer les paramètres du terminal
    tcsetattr(STDIN_FILENO, TCSANOW, &old_flags);
    printf("\n");
}

// Fonction pour dériver une clé à partir d'un mot de passe
int derive_key_from_password(unsigned char* key, const char* password) {
    unsigned char salt[SALT_SIZE];
    
    // Générer un sel aléatoire
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        handle_openssl_error();
        return -1;
    }
    
    // Dériver la clé avec PBKDF2
    if (PKCS5_PBKDF2_HMAC(password, strlen(password),
                          salt, SALT_SIZE,
                          ITERATIONS,
                          EVP_sha256(),
                          KEY_SIZE, key) != 1) {
        handle_openssl_error();
        return -1;
    }
    
    // Sauvegarder le sel avec la clé
    FILE* salt_file = fopen("salt.bin", "wb");
    if (salt_file == NULL) {
        fprintf(stderr, "Erreur: Impossible de sauvegarder le sel\n");
        return -1;
    }
    
    fwrite(salt, 1, SALT_SIZE, salt_file);
    fclose(salt_file);
    
    return 0;
}

// Modifier la fonction generate_key_file pour utiliser la dérivation de clé
void generate_key_file(unsigned char* key, const char* output_file) {
    time_t now = time(NULL);
    char filename[100];
    FILE* key_file;
    char password[128];
    
    // Demander le mot de passe à l'utilisateur
    read_password(password, sizeof(password));
    
    // Dériver la clé à partir du mot de passe
    if (derive_key_from_password(key, password) != 0) {
        fprintf(stderr, "Erreur lors de la dérivation de la clé\n");
        exit(EXIT_FAILURE);
    }
    
    // Créer le nom du fichier avec timestamp
    sprintf(filename, "key-%ld-%s.bin", now, output_file);
    
    // Sauvegarder la clé dans un fichier
    key_file = fopen(filename, "wb");
    if (key_file == NULL) {
        fprintf(stderr, "Erreur: Impossible de créer le fichier de clé\n");
        exit(EXIT_FAILURE);
    }
    
    fwrite(key, 1, KEY_SIZE, key_file);
    fclose(key_file);
    printf("Clé sauvegardée dans: %s\n", filename);
    
    // Effacer le mot de passe de la mémoire
    memset(password, 0, sizeof(password));
}

// Fonction pour calculer le MAC sur le fichier chiffré
int compute_etm_signature(const char* encrypted_file, const unsigned char* key) {
    FILE *file = NULL;
    unsigned char buffer[4096];
    size_t bytes_read;
    unsigned char hmac[EVP_MAX_MD_SIZE];
    size_t hmac_len;
    
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
    
    // Initialiser HMAC avec la clé
    if (!EVP_MAC_init(mac_ctx, key, KEY_SIZE, params)) {
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac);
        return -1;
    }
    
    // Lire et calculer le MAC sur le fichier chiffré complet
    file = fopen(encrypted_file, "rb");
    if (!file) {
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac);
        return -1;
    }
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (!EVP_MAC_update(mac_ctx, buffer, bytes_read)) {
            fclose(file);
            EVP_MAC_CTX_free(mac_ctx);
            EVP_MAC_free(mac);
            return -1;
        }
    }
    
    fclose(file);
    
    // Calculer le MAC final
    if (!EVP_MAC_final(mac_ctx, hmac, &hmac_len, sizeof(hmac))) {
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac);
        return -1;
    }
    
    // Nettoyage
    EVP_MAC_CTX_free(mac_ctx);
    EVP_MAC_free(mac);
    
    // Sauvegarder le MAC
    return store_signature(encrypted_file, hmac, (unsigned int)hmac_len);
}

// Fonction pour chiffrer un fichier avec AES en mode CBC ou GCM
int encrypt_file(const char* input_file, const char* output_file, CipherMode mode) {
    FILE *in_file, *out_file;
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    unsigned char key[KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char buffer[4096];
    unsigned char out_buffer[4096 + EVP_MAX_BLOCK_LENGTH];
    int in_len, out_len, final_len;
    
    // Initialiser OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Générer la clé
    generate_key_file(key, output_file);
    
    // Générer l'IV
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        handle_openssl_error();
    }
    
    // Créer le contexte de chiffrement
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        handle_openssl_error();
    }
    
    // Sélectionner le mode de chiffrement
    if (mode == CBC_MODE) {
        cipher = EVP_aes_256_cbc();
    } else if (mode == GCM_MODE) {
        cipher = EVP_aes_256_gcm();
    } else {
        fprintf(stderr, "Mode de chiffrement non supporté\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Initialiser le chiffrement
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        handle_openssl_error();
    }
    
    // Ouvrir les fichiers
    in_file = fopen(input_file, "rb");
    if (in_file == NULL) {
        fprintf(stderr, "Erreur: Impossible d'ouvrir le fichier d'entrée\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    out_file = fopen(output_file, "wb");
    if (out_file == NULL) {
        fprintf(stderr, "Erreur: Impossible de créer le fichier de sortie\n");
        fclose(in_file);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Écrire l'IV au début du fichier chiffré
    fwrite(iv, 1, AES_BLOCK_SIZE, out_file);
    
    // Chiffrer le fichier
    while ((in_len = fread(buffer, 1, sizeof(buffer), in_file)) > 0) {
        if (EVP_EncryptUpdate(ctx, out_buffer, &out_len, buffer, in_len) != 1) {
            handle_openssl_error();
        }
        if (out_len > 0) {
            fwrite(out_buffer, 1, out_len, out_file);
        }
    }
    
    // Finaliser le chiffrement
    if (EVP_EncryptFinal_ex(ctx, out_buffer, &final_len) != 1) {
        handle_openssl_error();
    }
    if (final_len > 0) {
        fwrite(out_buffer, 1, final_len, out_file);
    }
    
    // Pour GCM, écrire le tag d'authentification
    if (mode == GCM_MODE) {
        unsigned char tag[16];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
            handle_openssl_error();
        }
        fwrite(tag, 1, 16, out_file);
    }
    
    // Fermer les fichiers
    fclose(in_file);
    fclose(out_file);
    EVP_CIPHER_CTX_free(ctx);
    
    // Calculer et sauvegarder le MAC (Encrypt-then-MAC)
    if (compute_etm_signature(output_file, key) != 0) {
        fprintf(stderr, "Erreur lors de la génération de la signature\n");
        return -1;
    }
    
    printf("Fichier chiffré avec succès en mode %s!\n", 
           mode == CBC_MODE ? "CBC" : "GCM");
    
    return 0;
}

// Fonction pour calculer la signature
int compute_signature(const char* encrypted_file, const char* original_file, const unsigned char* key) {
    FILE *file = NULL;
    unsigned char buffer[4096];
    size_t bytes_read;
    unsigned char hmac[EVP_MAX_MD_SIZE];
    size_t hmac_len;
    
    // Créer le contexte EVP_MAC
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        fprintf(stderr, "Erreur lors de la création du contexte MAC\n");
        return -1;
    }
    
    // Créer le contexte MAC
    EVP_MAC_CTX *mac_ctx = EVP_MAC_CTX_new(mac);
    if (!mac_ctx) {
        fprintf(stderr, "Erreur lors de la création du contexte MAC\n");
        EVP_MAC_free(mac);
        return -1;
    }
    
    // Paramètres pour HMAC-SHA256
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_END
    };
    
    // Initialiser HMAC avec la clé
    if (!EVP_MAC_init(mac_ctx, key, KEY_SIZE, params)) {
        fprintf(stderr, "Erreur lors de l'initialisation MAC\n");
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac);
        return -1;
    }
    
    // Lire et mettre à jour MAC avec le contenu du fichier chiffré
    file = fopen(encrypted_file, "rb");
    if (!file) {
        fprintf(stderr, "Erreur lors de l'ouverture du fichier chiffré\n");
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac);
        return -1;
    }
    
    // Sauter l'IV avant de calculer le MAC
    fseek(file, AES_BLOCK_SIZE, SEEK_SET);
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        EVP_MAC_update(mac_ctx, buffer, bytes_read);
    }
    
    fclose(file);
    
    // Calculer la valeur MAC finale
    if (!EVP_MAC_final(mac_ctx, hmac, &hmac_len, sizeof(hmac))) {
        fprintf(stderr, "Erreur lors de la finalisation MAC\n");
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac);
        return -1;
    }
    
    // Nettoyage
    EVP_MAC_CTX_free(mac_ctx);
    EVP_MAC_free(mac);
    
    // Stocker la signature
    return store_signature(encrypted_file, hmac, (unsigned int)hmac_len);
}

// Fonction pour stocker la signature dans un fichier
int store_signature(const char* encrypted_file, const unsigned char* signature, unsigned int sig_len) {
    char sig_filename[1024];
    FILE* sig_file;
    
    
    // Créer le nom du fichier de signature
    snprintf(sig_filename, sizeof(sig_filename), "%s.sig", encrypted_file);
    
    // Ouvrir le fichier de signature
    sig_file = fopen(sig_filename, "wb");
    if (!sig_file) {
        fprintf(stderr, "Erreur lors de la création du fichier de signature\n");
        return -1;
    }
    
    // Écrire la signature
    if (fwrite(signature, 1, sig_len, sig_file) != sig_len) {
        fprintf(stderr, "Erreur lors de l'écriture de la signature\n");
        fclose(sig_file);
        return -1;
    }
    
    fclose(sig_file);
    printf("Signature sauvegardée dans: %s\n", sig_filename);
    return 0;
}

CipherMode parse_mode(const char* mode_str) {
    if (strcmp(mode_str, "CBC") == 0) return CBC_MODE;
    if (strcmp(mode_str, "GCM") == 0) return GCM_MODE;
    return UNKNOWN_MODE;
}

void print_usage() {
    printf("Usage: aes <mode> <input_file> <output_file>\n");
    printf("Modes disponibles: CBC, GCM\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        print_usage();
        return 1;
    }
    
    CipherMode mode = parse_mode(argv[1]);
    if (mode == UNKNOWN_MODE) {
        fprintf(stderr, "Erreur: Mode de chiffrement invalide\n");
        print_usage();
        return 1;
    }
    
    return encrypt_file(argv[2], argv[3], mode);
}