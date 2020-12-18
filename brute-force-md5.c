/* Copyright: Que Le */
/* Education purpose only! */

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#define MAX_PASS_LENGTH 15
#define BUFFS_PER_THREAD 30
#define BUFF_LENGTH 64   // this is not necessary to be same as pass length but rather efficiently mem usage (x bytes * 8bits/byte)

#define SIGNAL_FOUND_PASSWORD 2
#define SIGNAL_USER_FORCE_QUIT 0

// Samples: 
// aaaaaaaaaelmkfg  => 032c62a80cc5d261fff49492dab53653
// hello            => 5d41402abc4b2a76b9719d911017c592
// delmkfg          => 5f2b20619f83e738848530888a454bc3
// ghwu             => 375a365192149ce58d849af327779b29

//clang -Wall brute-force-md5.c -o brute-force-md5 -lssl -lcrypto -lm -pthread && time ./brute-force-md5 5d41402abc4b2a76b9719d911017c592 8 15 v

int nbr_threads = 1;
int pass_length = 5;
int verbose = 0;
unsigned long long int total_combination = 0;
char target_md5[33];
char alphabet[26] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'};

static volatile sig_atomic_t keep_running = 1;

static void sig_handler(int _)
{
    (void)_;
    keep_running = 0;
}

struct hash_thread_arg
{
    int id;
    unsigned long long int iteration;
    int first_buff_pos; 
    int last_buff_pos; 
    char** buffs;
};

struct gen_thread_arg
{
    int id;
    char** buffs;
};

void bytes2md5(const char *data, int len, char *md5buf) {
    // Code example from https://stackoverflow.com/a/61333376/13039751
    // Based on https://www.openssl.org/docs/manmaster/man3/EVP_DigestUpdate.html
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);
    for (i = 0; i < md_len; i++) {
        snprintf(&(md5buf[i * 2]), 16 * 2, "%02x", md_value[i]);
    }
}

static void *
thread_test_hash(void *arg)
{
    int buff_th = 0;
    int thread_id = ((struct hash_thread_arg *)arg)->id;
    int first_buff_pos = ((struct hash_thread_arg *)arg)->first_buff_pos;
    int last_buff_pos = ((struct hash_thread_arg *)arg)->last_buff_pos;
    char md5[33]; // 32 characters + null terminator

    printf("thread id: %d, buffer from %d to %d\n", thread_id, first_buff_pos, last_buff_pos);
    while(1) {
        if (keep_running == 0) {
            printf("thread_test_hash id=%d : Task canceled by user. Exit\n", thread_id);
            return NULL;
        } else if (keep_running == 2) {
            printf("thread_test_hash id=%d : Found pasword. Exit.\n", thread_id);
            return NULL;
        } 
        if (strlen(((struct hash_thread_arg *)arg)->buffs[first_buff_pos + buff_th]) != 0) {
            if (verbose==1) {
                printf("thread id=%d testing password candidate: %s\n", 
                                ((struct hash_thread_arg *)arg)->id,
                                ((struct hash_thread_arg *)arg)->buffs[first_buff_pos + buff_th]
                                );
            }

            ((struct hash_thread_arg *)arg)->iteration +=1;
            bzero(md5, 33);
            bytes2md5(
                    ((struct hash_thread_arg *)arg)->buffs[first_buff_pos + buff_th], 
                    strlen(((struct hash_thread_arg *)arg)->buffs[first_buff_pos + buff_th]), 
                    md5);
            if (strcmp(md5, target_md5) == 0) {
                printf("===>>>>>>>\nThread %d found password: %s\nInput: %s\nCalc : %s\n<<<<<<<===\n",
                            thread_id,
                            ((struct hash_thread_arg *)arg)->buffs[first_buff_pos + buff_th],
                            target_md5, md5);
                keep_running = SIGNAL_FOUND_PASSWORD;
                return NULL;
            }

            // Done. Clear the buffer so generator can fill it up again
            ((struct hash_thread_arg *)arg)->buffs[first_buff_pos + buff_th][0] = '\0';
            buff_th = (buff_th + 1) % BUFFS_PER_THREAD;
        }
        // struct timespec reg = {0, 10000000};
        // struct timespec rem;
        // nanosleep(&reg, &rem);
    }
    return NULL;
}


static void *
thread_generate_string(void *arg)
{
    printf("String generation id=%d\n", ((struct gen_thread_arg *)arg)->id);
    int n = 0;
    unsigned long long int count = 0;
    // for (int i=1; i<=pass_length; i++) {
    //     total_combination += pow(i, sizeof(alphabet)/sizeof(alphabet[0])+1);
    //     printf("i:%d %d %lld\n", i, sizeof(alphabet)/sizeof(alphabet[0])+1, total_combination);
    // }
    for (n=1; n <= pass_length; n++) {
        // Base on https://stackoverflow.com/a/40938850/13039751
        int k = sizeof(alphabet)/sizeof(alphabet[0]);
        int row, col; 
        int cell;
        int rdiv;
        unsigned long long int nbr_comb = pow(k+1, n);
        int gen_string_saved = 0;
        char temp[BUFF_LENGTH];
        int pos;
        for (row=0; row < nbr_comb; row++) 
        {
            if (keep_running == SIGNAL_USER_FORCE_QUIT) {
                printf("thread_generate_string: Task canceled by user. Exit. Count = %lld\n", count);
                return NULL;
            } else if (keep_running == SIGNAL_FOUND_PASSWORD) {
                printf("thread_generate_string: Found pasword. Exit. Generated: %lld password candidates.\n", count);
                return NULL;
            }
            gen_string_saved = 0;
            bzero(temp, BUFF_LENGTH);
            pos = 0;
            for (col=n-1; col>=0; col--)
            {
                rdiv = pow(k+1, col);
                cell = (row/rdiv) % (k+1);
                //printf("%c |", alphabet[cell]);
                temp[pos] = alphabet[cell];
                pos += 1;
                count += 1;
            }
            temp[pos] = '\0';
            
            while(gen_string_saved != 1) {
                if (keep_running == SIGNAL_USER_FORCE_QUIT) {
                    printf("thread_generate_string: Task canceled by user. Exit. Count = %lld\n", count);
                    return NULL;
                } else if (keep_running == SIGNAL_FOUND_PASSWORD) {
                    printf("thread_generate_string: Found pasword. Exit. Generated: %lld password candidates.\n", count);
                    return NULL;
                }
                // Look for cell to put the gen string in BUFFERS
                for (int buff_th = 0; buff_th<nbr_threads*BUFFS_PER_THREAD; buff_th++) {
                    if (strlen(((struct gen_thread_arg *)arg)->buffs[buff_th]) == 0) {
                        bzero(((struct gen_thread_arg *)arg)->buffs[buff_th], BUFF_LENGTH);    // overkill ...
                        strcpy(((struct gen_thread_arg *)arg)->buffs[buff_th], temp);
                        ((struct gen_thread_arg *)arg)->buffs[buff_th][pos] = '\0';
                        gen_string_saved = 1;
                        //printf("__Generated: %s at i=%d\n", ((struct gen_thread_arg *)arg)->buffs[buff_th], buff_th);
                        break;
                    }
                }
            }
            //printf("\n");
            //struct timespec reg = {0, 10000000};
            //struct timespec rem;
            //nanosleep(&reg, &rem);
        }
    }
    printf("Count = %lld\n", count);
    return NULL;
}

int main(int argc, char *argv[]) {
    /* Parsing arguments */
    if (argc < 4) {
        perror("Input: <hash string>  <number of thread> <pass_length>. Exit ...\n");
        exit(EXIT_FAILURE);
    }
    if (strlen(argv[1]) != 32) {
        perror("Hash string need to be 32 char length. Exit ...\n");
        exit(EXIT_FAILURE);
    } else {
        strcpy(target_md5, argv[1]);
        target_md5[32] = '\0';
    }

    int temp = atoi(argv[2]);
    if (temp <1 || temp>9) {
        perror("Number of thread need to be greater than 1 and smaller than 10. Exit ...\n");
        exit(EXIT_FAILURE);
    }
    nbr_threads = temp;

    temp = atoi(argv[3]);
    if (temp <1) {
        perror("Pass length need to be greater than 1. Exit ...\n");
        exit(EXIT_FAILURE);
    }
    pass_length = temp;

    if (argc >= 5 && strcmp(argv[4], "v") == 0) {
        verbose = 1;
    }
    printf("Hash string: %s, threads: %d\n", target_md5, nbr_threads);

    /* Handle Ctrl+C */
    signal(SIGINT, sig_handler);

    /* Prepare buffer to store generated strings */
    char* buffers[nbr_threads*BUFFS_PER_THREAD];
    for (int i=0; i<nbr_threads*BUFFS_PER_THREAD; i++) {
        buffers[i] = malloc( sizeof(char) * BUFF_LENGTH );
        buffers[i][0] = '\0';
    }

    /* Threading for generating string from alphabet*/
    pthread_t gen_t_id;
    struct gen_thread_arg g_t_arg;
    g_t_arg.id = 0;
    g_t_arg.buffs = buffers;
    pthread_create(&gen_t_id, NULL, thread_generate_string, &g_t_arg);

    /* Threading for calculating and comparing hash value */
    struct hash_thread_arg hash_t_args[nbr_threads];
    for (int i=0; i<nbr_threads; i++) {
        hash_t_args[i].first_buff_pos = i*BUFFS_PER_THREAD;
        hash_t_args[i].last_buff_pos = (i+1)*BUFFS_PER_THREAD-1;
        hash_t_args[i].id = i;
        hash_t_args[i].iteration = 0;
        hash_t_args[i].buffs = buffers;
    }
    pthread_t hash_thread_ids[nbr_threads];
    for (int i=0; i<nbr_threads; i++) {
        pthread_create(&hash_thread_ids[i], NULL, thread_test_hash, &hash_t_args[i]); 
    }

    /* Simple stats */
    while (keep_running ==1 )
    {
        unsigned long long int tested_comb = 0;
        if (total_combination > 0) {
            for (int i=0; i<nbr_threads; i++) {
                tested_comb += hash_t_args[i].iteration;
            }
            float p = 100*((float)(tested_comb)/(float)(total_combination));
            printf("Processed: %.2f (%lld of %lld)\n", p, tested_comb, total_combination);
        }
        sleep(1);
    }
    

    /* Join threads */
    pthread_join(gen_t_id, NULL);
    for (int i=0; i<nbr_threads; i++) {
        pthread_join(hash_thread_ids[i], NULL);
    }

    /* Free */
    for (int i=0; i<nbr_threads*BUFFS_PER_THREAD; i++) {
        free(buffers[i]);
    }
    return 1;
}
