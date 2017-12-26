#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/time.h>

#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <math.h>

#define ERROR         -1
#define MAX_CLIENTS   10
#define MAX_DATA      4096
#define MAX(a,b)      (((a)>(b))?(a):(b))


struct ctr_state 
{ 
  unsigned char ivec[AES_BLOCK_SIZE];  
  unsigned int num; 
  unsigned char ecount[AES_BLOCK_SIZE]; 
}; 


AES_KEY key;  

void init_ctr(struct ctr_state *state, const unsigned char iv[16])
{    
  /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
     * first call. */
    state->num = 0;
    //memset(state->ecount, 0, AES_BLOCK_SIZE);

    memset(state->ecount, 0, 8);

    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
    
}

/* 
  This is proxy_server and shall be up on proxy_port given along with -l flag.
  it should forward all the bytes it received from proxy_port to <dest_ip>:<dest_port>
  which is the protected server.

  from    proxy_port              to    <dest_ip>:<dest_port>
  from    <dest_ip>:<dest_port>   to    proxy_port

  it should be bidirectional and for that we use select function.

  client is outsider who is connected to this.
*/



  int main(int argc, char **argv)
  {
    int kflag = 0, isServer = 0;
    int proxy_port = 0;
    int dest_port = 0;
    char dest_ip[20] = "";
    char key_filename[200] = "";
    if(argc < 2)
    {
      return(-1);
    }
    if(argc > 1)
    {
      int c;
      while ((c = getopt (argc, argv, "k:l:")) != -1)
      {
        switch (c)
        {
          case 'k':
          kflag = 1;
          strcat(key_filename, optarg);
          break;

          case 'l':
          isServer = 1;
          proxy_port = atoi(optarg);
          break;

        }
      }

      if(strcmp(argv[optind], "localhost") == 0)
      {
        strcat(dest_ip, "127.0.0.1");
      }
      else
      {
        strcat(dest_ip, argv[optind]);
      }
      dest_port = atoi(argv[optind+1]);
    }
    unsigned char* enc_key;
    unsigned char* decimal_string;
    if(kflag == 0)
    {
      decimal_string = (unsigned char *)"50515253545556575859606162636465";
    }
    else
    {
      //initialize the enc_key
      FILE *key_f = fopen(key_filename, "rb");//rb-read binary
      if(!key_f)
      {
        printf("Unable to open given key_filename\n");
        return (-1);
      }
      fseek(key_f, 0, SEEK_END);
      long length = ftell(key_f);
      fseek(key_f, 0, SEEK_SET);
      //enc_key = malloc(length);
      decimal_string = (unsigned char *) malloc(length);
      fread(decimal_string, 1, length, key_f);
      fclose(key_f);
    }

    //convert decimal_string into enc_key
    int max_bytes = 17;
    char temporary[max_bytes];

        enc_key = (unsigned char *) malloc(max_bytes);
        int value;
        int i;
        for(i=0;i<strlen((const char*)decimal_string)-1;i=i+2){

            value = 16*( *(decimal_string+i)-'0' ) + *(decimal_string+i+1)-'0' ;
            temporary[i/2] = (char)value;

        }
        temporary[max_bytes-1] = '\0';
        strcpy((char *)enc_key,temporary);
    


    if(isServer)
    {
        struct sockaddr_in proxy_server;
        struct sockaddr_in client;
        int sock; //fd for proxy_port, binded to proxy_server
        int client_descriptor; 
        unsigned int  sockaddr_len = sizeof(struct sockaddr_in);
        int data_len = 0;
        char data[MAX_DATA];

        if((sock = socket(AF_INET, SOCK_STREAM, 0)) == ERROR)
        {
          printf("socket() failed!");
          return(-1);
        }

        proxy_server.sin_family = AF_INET;
        //proxy_server.sin_port = htons(atoi(argv[1]));
        proxy_server.sin_port = htons((proxy_port));
        proxy_server.sin_addr.s_addr = INADDR_ANY;
        //bzero(&proxy_server.sin_zero, 8);
        memset(&proxy_server.sin_zero, 0, 8);

        if((bind(sock, (struct sockaddr *)&proxy_server, sockaddr_len)) == ERROR)
        {
          printf("bind() failed! \n");
          return(-1);
        }

        if((listen(sock, MAX_CLIENTS)) == ERROR)
        {
          printf("listen() failed!\n");
          return(-1);
        }

        //set of socket descriptors
        fd_set read_fds;
        int maxfd;
        while(1)
        {
          if((client_descriptor = accept(sock, (struct sockaddr *)&client, &sockaddr_len)) == ERROR)
          {
            printf("accept() failed! \n");
            return(-1);
          }

          // bringing up the socket for the communication from real server
          struct sockaddr_in real_server;

          int real_sock;//fd for connection to real server
          if((real_sock = socket(AF_INET, SOCK_STREAM, 0)) == ERROR)
          {
            printf("real socket() failed!");
            return(-1);
          }
          real_server.sin_family = AF_INET;
          real_server.sin_port = htons((dest_port));
          real_server.sin_addr.s_addr = inet_addr(dest_ip);
          //bzero(&real_server.sin_zero, 8);
          memset(&real_server.sin_zero, 0, 8);

          if((connect(real_sock, (struct sockaddr *)&real_server, sizeof(struct sockaddr_in))) == ERROR)
          {
            printf("real sock connect() failed!\n");
            return(-1);
          }
          unsigned char iv_decrypt[AES_BLOCK_SIZE],iv_encrypt[AES_BLOCK_SIZE];
          struct ctr_state state_decrypt, state_encrypt;

          // recive rand iv from clien
          // use for decrypt
          
          read(client_descriptor, iv_decrypt, AES_BLOCK_SIZE);
          

          // gen rand iv
          // send iv to client
          // use for encryption
          if(!RAND_bytes(iv_encrypt, AES_BLOCK_SIZE))
          {
            printf("could not create random bytes\n");
          }
          // sending the above generated iv to 
          write(client_descriptor, iv_encrypt, AES_BLOCK_SIZE);
          

          // init_states for both different 
          init_ctr(&state_encrypt, iv_encrypt);
          init_ctr(&state_decrypt, iv_decrypt);

          // get the key
          if(AES_set_encrypt_key(enc_key, 128, &key) < 0)
          {
            printf("could not set decryption key\n");
          }

          while(1)
          {
            memset(data, 0, MAX_DATA);
            // initialize the read_fds with zeros
            // add real_sock(fd for real server) and sock(fd for proxy_port) to read_fds
            FD_ZERO(&read_fds);
            FD_SET(client_descriptor, &read_fds);
            FD_SET(real_sock, &read_fds);

            maxfd = MAX(client_descriptor, real_sock) + 1;
            if(select(maxfd, &read_fds, NULL, NULL, NULL) == -1)
            {
              return(-1);
            }
            else
            {

              // check if any client is trying to connect to a proxy_port 
              // if connected receive the data from client and send to real server
              if(FD_ISSET(client_descriptor, &read_fds))
              {
                
                  data_len = read(client_descriptor, data, MAX_DATA);
            
                  if(data_len == -1)
                  {
                    close(client_descriptor);
                    close(real_sock);
                    break;
                  }
                  if(data_len > 0)
                  {
                    // before writing the data into real server socket we have to decrypt the data
                    char decrypted[data_len];
                    AES_ctr128_encrypt((const unsigned char*)data, (unsigned char*)decrypted, data_len, &key, state_decrypt.ivec, state_decrypt.ecount, &state_decrypt.num);


                    if(write(real_sock, decrypted, data_len) == -1)
                    {
                      return(-1);
                    }
                  }
                  else
                  {
                    close(client_descriptor);
                    close(real_sock);
                    break;
                  }
              }

              
              
              // check if there is something from the real server connected to this,
              // if so we should send it back to 
              // sock (fd for proxy_port) where other public clients are connected to
              if(FD_ISSET(real_sock, &read_fds))
              {
                
                  data_len = read(real_sock, data, MAX_DATA);
                  if(data_len == -1)
                  {
                    close(client_descriptor);
                    close(real_sock);
                    return(-1);
                  }
                  if(data_len > 0)
                  {
                    //before writing we have to encrypt and send data to client
                    char encrypted[data_len];
                    AES_ctr128_encrypt((const unsigned char*)data, (unsigned char*)encrypted, data_len, &key, state_encrypt.ivec, state_encrypt.ecount, &state_encrypt.num);

                    if(write(client_descriptor, encrypted, data_len)== -1)
                    {
                      return(-1);
                    }
                  
                  }
                  else
                  {
                    close(client_descriptor);
                    close(real_sock);
                    break;
                  }
              } 


            }
          }
          
        }

        close(sock);
        return(0);
      }
      else
      {
        struct sockaddr_in remote_server;
        struct sockaddr_in client;
        int sock;
        unsigned int  sockaddr_len = sizeof(struct sockaddr_in);
        int client_descriptor; 

        if((sock = socket(AF_INET, SOCK_STREAM, 0)) == ERROR)
        {
          printf("socket() failed!");
          return(-1);
        }

        remote_server.sin_family = AF_INET;
        remote_server.sin_port = htons(dest_port);
        remote_server.sin_addr.s_addr = inet_addr(dest_ip);
        memset(&remote_server.sin_zero, 0, 8);

        if((connect(sock, (struct sockaddr *)&remote_server, sizeof(struct sockaddr_in)))==ERROR)
        {
          printf("connect() failed!\n");
          return(-1);
        }

        //set of socket descriptors
        fd_set read_fds;
        int maxfd;

        int data_len;
        char data[MAX_DATA];

        // generate rand iv
        // send rand iv to pbserver
        // use this for encryption along with key
        unsigned char iv_encrypt[AES_BLOCK_SIZE],iv_decrypt[AES_BLOCK_SIZE];
        struct ctr_state state_encrypt, state_decrypt;

        if(!RAND_bytes(iv_encrypt, AES_BLOCK_SIZE))
        {
          printf("could not create random bytes\n");
        }

        write(sock, iv_encrypt, AES_BLOCK_SIZE);


        //rec rand iv from pbserver
        // decrypt
        read(sock, iv_decrypt, AES_BLOCK_SIZE);


        // init_states for both different
        init_ctr(&state_encrypt, iv_encrypt);
        init_ctr(&state_decrypt, iv_decrypt);



        // get the key
        if(AES_set_encrypt_key(enc_key, 128, &key) < 0)
        {
          printf("could not set decryption key\n");
        }



        while(1)
        {
          memset(data, 0, MAX_DATA);
          // initialize the read_fds with zeros
          // add 0(fd for stdin) and sock(fd for remote_server) to read_fds
          FD_ZERO(&read_fds);
          FD_SET(0, &read_fds);
          FD_SET(sock, &read_fds);

          maxfd = MAX(0, sock) + 1;
          if(select(maxfd, &read_fds, NULL, NULL, NULL) == -1)
          {
            return(-1);
          }
          else
          {
            // check if there is anything on the stdin  
            // if so receive the data from stdin and send to sock (fd for remote_server)
            if(FD_ISSET(0, &read_fds))
            {
              data_len = read(0, data, MAX_DATA);
              if(data_len < 0)
              {
                break;
              }
              if(data_len == -1)
              {
                return(-1);
              }

              if(data_len > 0)
              {
                char encrypted[data_len];
                //before writing we have encrypt and send data
                AES_ctr128_encrypt((const unsigned char*)data, (unsigned char*)encrypted, data_len, &key, state_encrypt.ivec, state_encrypt.ecount, &state_encrypt.num);


                if(write(sock, encrypted, data_len) == -1)
                {
                  return(-1);
                }
                else
                {
                  data[data_len] = '\0';
                }
              }
              
            }

            // check if there is something from the sock (fd for remote server) connected to this,
            // if so then we should send it back to 0 (fd for stdin) 
            if(FD_ISSET(sock, &read_fds))
            {
              data_len = read(sock, data, MAX_DATA);
              if(data_len < 0)
              {
                break;
              }
              if(data_len == -1)
              {
                return(-1);
              }
              if(data_len > 0)
              {

                // decrypt the read data before writing to 1
                char decrypted[data_len];
                AES_ctr128_encrypt((const unsigned char*)data, (unsigned char*)decrypted, data_len, &key, state_decrypt.ivec, state_decrypt.ecount, &state_decrypt.num);

                if(write(1, decrypted, data_len) == -1)
                {
                  return(-1);
                }
              }
              
            }
          }

        }

        close(sock);
        return (0);
      }
    }