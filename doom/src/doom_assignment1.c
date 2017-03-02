/**
 * @doom_assignment1
 * @author  Do Om <doom@buffalo.edu>
 * @version 1.0
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @section DESCRIPTION
 *
 * This contains the main function. Add further description here....
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <limits.h>

#include "../include/global.h"
#include "../include/logger.h"
#include "../include/helper.h"
#include "../include/vector.h"
#define STDIN 0
#define BACKLOG 50
#define BUFSIZE 256

/**
 * main function
 *
 * @param  argc Number of arguments
 * @param  argv The argument list
 * @return 0 EXIT_SUCCESS
 */
int main(int argc, char **argv)
{
    /*Init. Logger*/
    cse4589_init_log(argv[2]);

    /*Clear LOGFILE*/
    fclose(fopen(LOGFILE, "w"));

    /*Start Here*/

    char *prompt = "[PA1]$ ";
    // Parse command line args
    if(argc != 3 ||\
       (strcmp(argv[1], "s") != 0 &&  strcmp(argv[1], "c") != 0) ||\
       !isValidInt(argv[2])) {
        puts("Usage:   ./assignment1 [server/client] [port]");
        puts("example: ./assignment1 s 4322");
        exit(EXIT_FAILURE);
    }

    // List of clients

    // Set up socket
    int fd, status;
    char *port = argv[2];
    struct addrinfo hints, *res, *rp;
    struct timeval tv;
    fd_set master, read_fds;
    FD_ZERO(&master);
    FD_ZERO(&read_fds);

    char host_name[1024];
    gethostname(host_name, 1024);
    // printf("host_name: %s\n", host_name);

    // int portno = atoi(port);
    // struct sockaddr_in sa;
    // fd = socket(AF_INET, SOCK_STREAM, 0);
    // bzero((char *)&sa, sizeof(sa));
    // sa.sin_family = AF_INET;
    // sa.sin_addr.s_addr = INADDR_ANY;
    // sa.sin_port = htons(portno);
    // bind(fd, (struct sockaddr *)&sa, sizeof(sa));
    // listen(fd, 5);

    // Get linked list of available addresses
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;    // IPv4
    hints.ai_socktype = SOCK_STREAM;    // Stream socket

    if( (status = getaddrinfo(host_name, port, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    // Loop to find usable address
    for(rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(fd == -1) continue;

        if(bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;

        close(fd);
    }

    if(rp == NULL) {
        fprintf(stderr, "Failed to bind\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    int fd_max;
    fd_max = fd;

    char ip_addr[INET_ADDRSTRLEN];
    struct sockaddr_in address;
    socklen_t len = sizeof(address);
    if(getsockname(fd, (struct sockaddr *) &address, &len) == -1) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }
    if(inet_ntop(AF_INET, &(address.sin_addr), ip_addr, INET_ADDRSTRLEN) == NULL) {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }
    int port_int = ntohs(address.sin_port);
    

    // Server Code
    nop();
    if(strcmp(argv[1], "s") == 0) {
        // List of clients
        Vector clients;
        vec_init(&clients);
        VectorStr msg_buffer;
        vecstr_init(&msg_buffer);

        // local testing
        // Listing l1;
        // listing_init(&l1);
        // strcpy(l1.hostname, "test1");
        // strcpy(l1.address, "128.0.0.3");
        // l1.port = 8888;
        // strcpy(l1.status, "logged-out");
        // Listing l2;
        // listing_init(&l2);
        // strcpy(l2.hostname, "test2");
        // strcpy(l2.address, "128.0.0.4");
        // l2.port = 5555;
        // Listing l3;
        // listing_init(&l3);
        // strcpy(l3.hostname, "test3");
        // strcpy(l3.address, "128.0.0.5");
        // l3.port = 77777;
        // vec_insert_sorted(&clients, &l1);
        // vec_insert_sorted(&clients, &l2);
        // vec_insert_sorted(&clients, &l3);


        if(listen(fd, BACKLOG) != 0) {
            perror("listen");
            exit(EXIT_FAILURE);
        } 
        
        char msg[256];
        char buf[512];
        int nbytes, new_fd;
        struct sockaddr_in remoteaddr;
        socklen_t addrlen;

        FD_SET(0, &master);
        FD_SET(fd, &master);
        // Listing listing;
        for(;;) {
            // write(1, prompt, strlen(prompt));
            memset(buf, '\0', sizeof(buf));
            read_fds = master;
            if(select(fd_max+1, &read_fds, NULL,\
                      NULL,  NULL) == -1) {
                perror("select");
                exit(EXIT_FAILURE);
            }
            for(int i = 0; i <= fd_max; i++) {
                if(FD_ISSET(i, &read_fds)) {
                    if(i == STDIN) {
                        // handle STDIN input
                        status = read(0, buf, sizeof(buf));
                        if(status == -1) {
                            perror("read from stdin");
                            exit(EXIT_FAILURE);
                        }
                        char *token;
                        if(status > 1) {
                            buf[status-1] = '\0';
                            token = strtok(buf, " ");
                        } else {
                            buf[0] = '\0';
                            token = buf;
                        }
                        // SHELL Commands
                        if(strcmp(token, "AUTHOR") == 0) {
                            // AUTHOR
                            status = sprintf(msg, "I, %s, have read and understood the course academic integrity policy.\n", "doom");
                            cse4589_print_and_log("[%s:SUCCESS]\n", "AUTHOR");
                            cse4589_print_and_log("%s\n", msg);
                            cse4589_print_and_log("[%s:END]\n", "AUTHOR");
                        } else if(strcmp(token, "IP") == 0) {
                            // IP
                            cse4589_print_and_log("[%s:SUCCESS]\n", "IP");
                            cse4589_print_and_log("IP:%s\n", ip_addr);
                            cse4589_print_and_log("[%s:END]\n", "IP");
                        } else if(strcmp(token, "PORT") == 0) {
                            // PORT
                            cse4589_print_and_log("[%s:SUCCESS]\n", "PORT");
                            cse4589_print_and_log("PORT:%d\n", port_int);
                            cse4589_print_and_log("[%s:END]\n", "PORT");
                        } else if(strcmp(token, "LIST") == 0) {
                            // LIST
                            cse4589_print_and_log("[%s:SUCCESS]\n", "LIST");
                            vec_print_list(&clients);
                            cse4589_print_and_log("[%s:END]\n", "LIST");

                        } else if(strcmp(token, "STATISTICS") == 0) {
                            // cse4589_print_and_log("[%s:SUCCESS]\n", "STATISTICS");
                            vec_print_statistic(&clients);
                            // cse4589_print_and_log("[%s:END]\n", "STATISTICS");
                        } else if(strcmp(token, "BLOCKED") == 0) {
                            char *client_ip = strtok(NULL, "");
                            // cse4589_print_and_log("[%s:SUCCESS]\n", "BLOCKED");
                            vec_print_blocked(&clients, client_ip);
                            // cse4589_print_and_log("[%s:END]\n", "BLOCKED");
                        }
                                                   

                    } else if(i == fd) {
                        // handle new connections
                        addrlen = sizeof(remoteaddr);
                        new_fd = accept(fd, (struct sockaddr *)&remoteaddr,
                                        &addrlen);
                        if(new_fd == -1) {
                            perror("accept");
                        } else {
                            FD_SET(new_fd, &master);
                            if(new_fd > fd_max) fd_max = new_fd;
                            // printf("selectserver: new connection fd: %d\n", new_fd);
                        }
                    } else {
                        // handle client messages
                        memset(buf, '\0', BUFSIZE);
                        // vec_print_list(&clients);
                        char payload[BUFSIZE];
                        int nbytes;
                        if( (nbytes = recv(i, buf, BUFSIZE, 0)) <= 0) {
                            if(nbytes == 0) {

                            } else {
                                perror("recv");
                            }
                            // printf("cleared %d\n", i);
                            close(i);
                            FD_CLR(i, &master);
                        } else {
                            // printf("received from client: %s\n", buf);
                            int k = 2;
                            char client_payload[BUFSIZE] = "";
                            // Check command received from client == BROADCAST
                            // printf("**payload: %s\n", client_payload);
                            strncpy(client_payload, &(buf[2]), nbytes-2);
                            // printf("buf before: %s\n", buf);
                            // printf("payload before: %s\n", client_payload);


                            // BROADCAST
                            if(strncmp("br", buf, 2) == 0) {
                                // printf("brconfirmed\n");
                                char *client_ip = strtok(client_payload, " ");
                                char *msg = strtok(NULL, "");
                                int msglen = strlen(msg);
                                if(msglen > 255) {
                                    msg[255] = 0;
                                }
                                int client_fd = vec_get_fd(&clients, client_ip);
                                char *payload;
                                // printf("clientfd: %d\n", client_fd);
                                cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");
                                cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", client_ip, "255.255.255.255", msg);
                                cse4589_print_and_log("[%s:END]\n", "RELAYED");

                                char to_client[512] = "";
                                char *head = "ms";
                                snprintf(to_client, sizeof(to_client), "%s%s %s", head, client_ip, msg);
                                char buf_msg[512] = "";
                                vecstr_append(&msg_buffer, to_client);
                                vec_msg_sent(&clients, client_ip);
                                for(int j = 4; j <= fd_max; j++) {
                                    // if(FD_ISSET(j, &master)) {
                                        // printf("j: %d\n", j);
                                        // if recvr is not blocked and logged in
                                        if(j != fd && j != client_fd && vec_is_blocked(&clients, client_ip, j) != 1 && vec_status(&clients, j) == 1) {
                                            if(send(j, to_client, strlen(to_client), 0) == -1) {
                                                perror("send");
                                            } else {
                                                vec_msg_recv_fd(&clients, j);
                                                // printf("fd: %d\nmsg: %s\n", j, msg);
                                            }
                                            
                                        } else if(j != fd && j != client_fd && vec_is_blocked(&clients, client_ip, j) != 1 && vec_status(&clients, j) == 0) {
                                            // If client is not blocked and logged out, add msg to client msg buffer
                                            // printf("add msg to buffer for fd: %d msg: %s\n", j, to_client);
                                            vec_add_msg(&clients, j, to_client);

                                        }
                                    // }
                                }
                                // vecstr_print(&msg_buffer);
                            }
                            // Check command received from client == SEND
                            if(strncmp("se", buf, 2) == 0) {
                                char *client_ip = strtok(client_payload, " ");
                                char *recvr_ip = strtok(NULL, " ");
                                char *message = strtok(NULL, "");
                                int len = strlen(message);    
                                if(len > 255) {
                                    message[255] = 0;
                                }               
                                char *head = "ms";           
                                // printf("ip: %s\nmessage: %s\n", client_ip, message);
                                int recvr_fd = vec_get_fd(&clients, recvr_ip);
                                // printf("recvr_fd: %d", recvr_fd);
                                char to_client[512] = "";
                                snprintf(to_client, sizeof(to_client), "%s%s %s", head, client_ip, message);
                                // if recvr exists and is not blocked and is logged in
                                if(recvr_fd >= 0 && vec_is_blocked(&clients, client_ip, recvr_fd) != 1 && vec_status(&clients, recvr_fd) == 1) {
                                    if(send(recvr_fd, to_client, strlen(to_client), 0) == -1) {
                                        perror("send");
                                    } else {
                                        // printf("sent %d bytes to fd=%d: %s\n", len, recvr_fd, message); 
                                        cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", client_ip, recvr_ip, message);
                                        vec_msg_sent(&clients, client_ip);
                                        vec_msg_recv(&clients, recvr_ip);
                                    }
                                } else if(recvr_fd >= 0 && vec_is_blocked(&clients, client_ip, recvr_fd) != 1 && vec_status(&clients, recvr_fd) == 0) {
                                    // if recvr exists and is not blocked and is not logged in
                                    // then save to recvr's msg buffer
                                    vec_add_msg(&clients, recvr_fd, to_client);
                                    vec_msg_sent(&clients, client_ip);

                                }
                            } 
                            // After login, receive and assign client listening port
                            if(strncmp("lo", buf, 2) == 0) {
                                struct sockaddr_in client_addr;
                                socklen_t addrsize = sizeof(client_addr);
                                int res = getpeername(new_fd, (struct sockaddr* )&client_addr, &addrsize);

                                char host[HOST_NAME_MAX];
                                char portstr[10];
                                char ip[INET_ADDRSTRLEN];
                                getnameinfo((struct sockaddr *)&client_addr, addrsize, host, sizeof(host), portstr, sizeof(portstr), 0);
                                inet_ntop(AF_INET, &(((struct sockaddr_in *)&client_addr)->sin_addr), ip, sizeof(ip));

                                Listing *listing = malloc(sizeof(Listing));
                                listing_init(listing);

                                // for localhost testing
                                char ip_localhost[INET_ADDRSTRLEN] = "127.0.1.1";
                                strncpy(listing->hostname, host, sizeof(listing->hostname));
                                strncpy(listing->address, ip, sizeof(listing->address));
                                sprintf(portstr, "%s", client_payload);
                                listing->port = atoi(portstr);
                                listing->fd = new_fd;
                				// printf("clientip: %s\n", ip_addr);

                                int result = vec_insert_sorted(&clients, listing);

                                // Send client list
                                char c_payload[2056] = "";
                                char head[3] = "li";
                                char client_list[2056] = "";
                                vec_clients(&clients, client_list);
                                snprintf(c_payload, sizeof(c_payload),"%s%s", head, client_list);
                                // printf("c_payload:\n%s\n", c_payload);
                                if(send(new_fd, c_payload, strlen(c_payload), 0) == -1) {
                                    perror("send");
                                }

                                if(result == -1) {
                                    // #TODO: send all buffered msgs to client
                                    // printf("result == -1 send all buffered msgs\n");
                                    for(int i = 0; i < msg_buffer.size; i++) {
                                        if(send(new_fd, msg_buffer.data[i], strlen(msg_buffer.data[i]), 0) == -1) {
                                            perror("send");
                                        }
                                        vec_msg_recv_fd(&clients, new_fd);
                                        // printf("sent: %s\n", msg_buffer.data[i]);
                                        char msg_ak[10];
                                        recv(new_fd, msg_ak, sizeof(msg_ak), 0);
                                        // printf("received ak: %s\n", msg_ak);
                                    }
                                } else {
                                    // #TODO: print out from client buf messages
                                    // printf("result != -1 print out from client buf msgs\n");
                                    VectorStr vs = clients.data[result]->buf_msg;
                                    // printf("vs.size: %d", vs.size);
                                    // printf("entering for loop\n");
                                    for(int i = 0; i < vs.size; i++) {
                                        if(send(new_fd, vs.data[i], strlen(vs.data[i]), 0) == -1) {
                                            perror("send");
                                        }
                                        vec_msg_recv_fd(&clients, new_fd);
                                        // printf("sent: %s\n", vs.data[i]);
                                        char msg_ak[10];
                                        recv(new_fd, msg_ak, sizeof(msg_ak), 0);
                                        // printf("received ak: %s\n", msg_ak);
                                    }
                                    for(int i = 0; i < vs.size; i++) {
                                        free(vs.data[i]);
                                    }
                                    vs.size = 0;


                                }
                            }

                            // REFRESH
                            if(strncmp("re", buf, 2) == 0) {
                                int client_fd = vec_get_fd(&clients, client_payload);        
                                // Check if invalid fd                       
                                if(client_fd == -1) {
                                    break;
                                }
                                // printf("refresh fd: %d\n", client_fd);
                                char *head = "re";
                                char client_list[2056] = "";
                                char payload[2056] = "";
                                vec_clients(&clients, client_list);
                                snprintf(payload, sizeof(payload), "%s%s", head, client_list);
                                int n;
                                if((n = send(client_fd, payload, strlen(payload), 0)) == -1) {
                                    perror("send");
                                }
                                // printf("sent bytes: %d\n", n);
                                // printf("payload:\n%s\n", payload);
                            }

                            if(strncmp("ex", buf, 2) == 0) {
                                // printf("head: ex\n");
                                // printf("cpayload: %s\n", client_payload);
                                vec_remove(&clients, client_payload);
                            }

                            if(strncmp("lg", buf, 2) == 0) {
                                vec_logout(&clients, client_payload);
                            }

                            if(strncmp("bl", buf, 2) == 0) {
                                // printf("bl: %s\n", client_payload);
                                char *client_ip = strtok(client_payload, " ");
                                char *block_ip = strtok(NULL, "");

                                char *head = "bs";
                                char payload[256] = "";
                                // int block_fd = vec_get_fd(&clients, block_ip);
                                int client_fd = vec_get_fd(&clients, client_ip);
                                if(vec_is_blocked(&clients, block_ip, client_fd) == 1) {
                                    snprintf(payload, sizeof(payload), "%s%s", head, "fail");
                                } else {
                                    vec_block(&clients, client_ip, block_ip);
                                    snprintf(payload, sizeof(payload), "%s%s", head, "success");
                                }
                                if(send(client_fd, payload, strlen(payload), 0) == -1) {
                                    perror("send");
                                }

                                // vec_print_blocked(&clients, client_ip);
                            }

                            if(strncmp("ub", buf, 2) == 0) {
                                // printf("ub: %s\n", client_payload);
                                char *client_ip = strtok(client_payload, " ");
                                char *unblock_ip = strtok(NULL, "");
                                // printf("entering vec_unblock\n");
                                char *head = "us";
                                char payload[256] = "";
                                int client_fd = vec_get_fd(&clients, client_ip);
                                if(vec_is_blocked(&clients, unblock_ip, client_fd) != 1) {
                                    snprintf(payload, sizeof(payload), "%s%s", head, "fail");
                                } else {
                                    vec_unblock(&clients, client_ip, unblock_ip);
                                    snprintf(payload, sizeof(payload), "%s%s", head, "success");
                                }
                                if(send(client_fd, payload, strlen(payload), 0) == -1) {
                                    perror("send");
                                }
                                // vec_print_blocked(&clients, client_ip);
                            }

                            if(strncmp("rl",buf, 2) == 0) {
                                vec_login(&clients, client_payload);
                            }

                        }

                    }
                }

            }
        }   // end for
        vec_free(&clients);
        vecstr_free(&msg_buffer);

    }



    // Client Code
    else {
        char clients_str[1024];
        bool logged_in = false;
        Vector clients;
        vec_init(&clients);

        if(listen(fd, BACKLOG) != 0) {
            perror("listen");
            exit(EXIT_FAILURE);
        } 

        char msg[256];
        char buf[1024];
        int nbytes, new_fd;
        struct sockaddr_storage remoteaddr;
        socklen_t addrlen;
        int server_fd = -1;

        FD_SET(0, &master);
        FD_SET(fd, &master);

        for(;;) {

            // write(1, prompt, strlen(prompt));
            memset(buf, '\0', sizeof(buf));
            read_fds = master;
            if(select(fd_max+1, &read_fds, NULL,\
                      NULL,  NULL) == -1) {
                perror("select");
                exit(EXIT_FAILURE);
            }
            for(int i = 0; i <= fd_max; i++) {
                if(FD_ISSET(i, &read_fds)) {
                    if(i == STDIN) {
                        status = read(0, buf, sizeof(buf));
                        if(status == -1) {
                            perror("read from stdin");
                            exit(EXIT_FAILURE);
                        }
                        char *token;
                        if(status > 1) {
                            buf[status-1] = '\0';
                            token = strtok(buf, " ");
                        } else {
                            buf[0] = '\0';
                            token = buf;
                        }
                        // printf("token = %s\n",  token);

                        if(strcmp(token, "AUTHOR") == 0) {
                            // AUTHOR
                            status = sprintf(msg, "I, %s, have read and understood the course academic integrity policy.\n", "doom");
                            cse4589_print_and_log("[%s:SUCCESS]\n", "AUTHOR");
                            cse4589_print_and_log("%s\n", msg);
                            cse4589_print_and_log("[%s:END]\n", "AUTHOR");
                        } else if(strcmp(token, "IP") == 0) {
                            // IP
                            // status = sprintf(msg, "IP:%s\n", ip_addr);
                            cse4589_print_and_log("[%s:SUCCESS]\n", "IP");
                            cse4589_print_and_log("IP:%s\n", ip_addr);
                            cse4589_print_and_log("[%s:END]\n", "IP");
                        } else if(strcmp(token, "PORT") == 0) {
                            // PORT
                            // status = sprintf(msg, "PORT:%d\n", port_int);
                            cse4589_print_and_log("[%s:SUCCESS]\n", "PORT");
                            cse4589_print_and_log("PORT:%d\n", port_int);
                            cse4589_print_and_log("[%s:END]\n", "PORT");
                        } else if(strcmp(token, "LIST") == 0) {
                            // LIST
                            cse4589_print_and_log("[%s:SUCCESS]\n", "LIST");
                            vec_print_list(&clients);
                            cse4589_print_and_log("[%s:END]\n", "LIST");

                        }

                        if(strcmp(token, "LOGIN") == 0 && logged_in == false) {
                            // LOGIN <server-ip> <server-port>
                            char *server_ip  = strtok(NULL, " ");
                            char *server_port = strtok(NULL, " ");
                            // printf("sip: %s\n", server_ip);
                            if(!isValidIP(server_ip)) {
                                cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
                                cse4589_print_and_log("[%s:END]\n", "LOGIN");
                            } else {
                                int server_port_int = atoi(server_port);
                                int len;
                                struct sockaddr_in server_addr;
                                if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                                    perror("LOGIN socket");
                                    exit(EXIT_FAILURE);
                                }
                                bzero(&server_addr, sizeof(server_addr));
                                server_addr.sin_family = AF_INET;
                                inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
                                server_addr.sin_port = htons(server_port_int);
                                memset(&hints, 0, sizeof(struct addrinfo));

                                if(connect(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
                                    cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
                                    cse4589_print_and_log("[%s:END]\n", "LOGIN");
                                    // perror("LOGIN connect");
                                    break;
                                }


                                FD_SET(server_fd, &master);
                                if(server_fd > fd_max) fd_max = server_fd;
                                // printf("selectserver: new connection fd: %d\n", server_fd);

                                // Send server client listening port
                                char *head = "lo";
                                char port_str[32];
                                memset(port_str, '\0', sizeof(port_str));
                                snprintf(port_str, sizeof(port_str), "%s%d", head, port_int);
                                // printf("sending port info: %s\n", port_str);
                                if(send(server_fd, port_str, strlen(port_str), 0) == -1) {
                                    perror("send");
                                }

                                logged_in = true;
                            }


                        } else if(strcmp(token, "REFRESH") == 0 && logged_in) {
                            // REFRESH
               


                            char payload[256];
                            char *head = "re";
                            snprintf(payload, sizeof(payload), "%s%s", head, ip_addr);
                            if(send(server_fd, payload, strlen(payload), 0) == -1) {
                                perror("send");
                            }
                            // printf("sent: %s\n", payload);

                        } else if(strcmp(token, "SEND")  == 0 && logged_in) {
                            // SEND <client-ip> <msg>
                            char payload[512];
                            char *head = "se";
                            char *client_ip = strtok(NULL, " ");
                            char *msg = strtok(NULL, "");
                            int msglen = strlen(msg);
                            if(msglen > 255) {
                                msg[255] = 0;
                            }
                            
                            // Check if valid ip
                            if(!isValidIP(client_ip) || !inClients(&clients, client_ip)) {
                                cse4589_print_and_log("[%s:ERROR]\n", "SEND");
                                cse4589_print_and_log("[%s:END]\n", "SEND");
                            } else {
                                snprintf(payload, sizeof(payload), "%s%s %s %s", head, ip_addr, client_ip, msg);
                                // printf("payload: %s\n", payload);
                                int len = strlen(payload);
                                if(server_fd != -1) {
                                    // Send to server
                                    if(send(server_fd, payload, len+1, 0) == -1) {
                                        perror("send");
                                    }
                                }
                                cse4589_print_and_log("[%s:SUCCESS]\n", "SEND");
                                cse4589_print_and_log("[%s:END]\n", "SEND");
                            }


                        } else if(strcmp(token, "BROADCAST") == 0) {
                            // BROADCAST <msg>
                            char payload[512];
                            char *head = "br";
                            char *message = strtok(NULL, "");
                            int msglen = strlen(message);
                            if(msglen > 255) {
                                message[255] = 0;
                            }

                            cse4589_print_and_log("[%s:SUCCESS]\n", "BROADCAST");
                            // cse4589_print_and_log(“BROADCAST:%s\n”, ip_addr);
                            // cse4589_print_and_log("%s\n", message);
                            cse4589_print_and_log("[%s:END]\n", "BROADCAST");

                            snprintf(payload, sizeof(payload), "%s%s %s", head, ip_addr, message);
                            if(server_fd != -1) {
                                // Send to server
                                if(send(server_fd, payload, strlen(payload), 0) == -1) {
                                    perror("send");
                                }
                                // write(1, message, len);

                            }

                        } else if(strcmp(token, "BLOCK") == 0) {
                            // BLOCK <client-ip>
                            char *client_ip = strtok(NULL, " ");
                            char payload[256] = "";
                            char *head = "bl";
                            if(!isValidIP(client_ip) || !inClients(&clients, client_ip)) {
                                cse4589_print_and_log("[%s:ERROR]\n", "BLOCK");
                                cse4589_print_and_log("[%s:END]\n", "BLOCK");
                            } else {
                                snprintf(payload, sizeof(payload), "%s%s %s", head, ip_addr, client_ip);
                                if(send(server_fd, payload, strlen(payload), 0) == -1) {
                                    perror("send");
                                }
                                // printf("block: %s\n", payload);
                                // cse4589_print_and_log("[%s:SUCCESS]\n", "BLOCK");
                                // cse4589_print_and_log("[%s:END]\n", "BLOCK");
                            }

                        } else if(strcmp(token, "UNBLOCK") == 0) {
                            // UNBLOCK <client-ip>

                            char *client_ip = strtok(NULL, " ");
                            char payload[256] = "";
                            char *head = "ub";
                            if(!isValidIP(client_ip) || !inClients(&clients, client_ip)) {
                                cse4589_print_and_log("[%s:ERROR]\n", "UNBLOCK");
                                cse4589_print_and_log("[%s:END]\n", "UNBLOCK");
                            } else {
                                snprintf(payload, sizeof(payload), "%s%s %s", head, ip_addr, client_ip);
                                if(send(server_fd, payload, strlen(payload), 0) == -1) {
                                    perror("send");
                                }
                                // cse4589_print_and_log("[%s:SUCCESS]\n", "UNBLOCK");
                                // cse4589_print_and_log("[%s:END]\n", "UNBLOCK");
                                // printf("unblock: %s\n", payload);
                            }

                        } else if(strcmp(token, "LOGOUT") == 0) {
                            cse4589_print_and_log("[%s:SUCCESS]\n", "LOGOUT");
                            cse4589_print_and_log("[%s:END]\n", "LOGOUT");
                            
                            char payload[256];
                            char *head = "lg";
                            snprintf(payload, sizeof(payload), "%s%s", head, ip_addr);
                            if(send(server_fd, payload, strlen(payload), 0) == -1) {
                                perror("send");
                            }

                            if(close(server_fd) == -1) {
                                perror("close");
                            }
                            // printf("cleared server_fd %d\n", server_fd);
                            FD_CLR(server_fd, &master);
                            server_fd = -1;

                            logged_in = false;

                        } else if(strcmp(token, "EXIT") == 0) {
                            // EXIT
                            // TODO: send signal to server
                            cse4589_print_and_log("[%s:SUCCESS]\n", "EXIT");
                            cse4589_print_and_log("[%s:END]\n", "EXIT");
                            vec_free(&clients);

                            char payload[256];
                            char *head = "ex";
                            snprintf(payload, sizeof(payload), "%s%s", head, ip_addr);
                            if(send(server_fd, payload, sizeof(payload), 0) == -1) {
                                perror("send");
                            }
                            exit(0);
                        } else if(strcmp(token, "SENDFILE") == 0) {
                            // SENDFILE <client-ip> <file>
                            cse4589_print_and_log("[%s:SUCCESS]\n", "SENDFILE");
                            cse4589_print_and_log("[%s:END]\n", "SENDFILE");


                            char *client_ip = strtok(NULL, " ");
                            char *file = strtok(NULL, " ");
                        }
                    } else if(i == fd) {
                        // handle new connections

                    } else {
                        // handle incoming messages
                        if( (nbytes = recv(i, buf, sizeof(buf), 0)) <= 0) {
                            if(nbytes == 0) {

                            } else {
                                perror("recv");
                            }
                            // printf("cleared %d", i);
                            close(i);
                            FD_CLR(i, &master);
                        } else {
                            // printf("nbytes = %d\n", nbytes);
                            int len = strlen(buf);
                            // printf("recvd %d bytes: %s\n", nbytes, buf);
                            char server_payload[BUFSIZE] = "";
                            strncpy(server_payload, &(buf[2]), nbytes-2);
                            // char *head = strtok(buf, " ");
                            // char *message = strtok(NULL, "");
                            // printf("head: %s\n", head);
                            // Received list of clients
                            if(strncmp("li", buf, 2) == 0) {
                                // printf("message: %s\n", message);
                                cse4589_print_and_log("[%s:SUCCESS]\n", "LOGIN");
                                vec_free(&clients);
                                vec_init(&clients);
                                vec_create(&clients, server_payload);
                                // vec_print_list(&clients);
                                // memset(clients, '\0', sizeof(clients));
                                // strncpy(clients, server_payload, strlen(server_payload));
                                // printf("%s", clients);
                                cse4589_print_and_log("[%s:END]\n", "LOGIN");
                                
                            }
                            if(strncmp("re", buf, 2) == 0) {
                                cse4589_print_and_log("[%s:SUCCESS]\n", "REFRESH");
                                // memset(clients, '\0', sizeof(clients));
                                // strncpy(clients, server_payload, strlen(server_payload));
                                vec_free(&clients);
                                vec_init(&clients);
                                // printf("payload: %s\n", server_payload);
                                vec_create(&clients, server_payload);
                                // vec_print_list(&clients);

                                cse4589_print_and_log("[%s:END]\n", "REFRESH");
                            }

                            if(strncmp("se", buf, 2) == 0) {
                                cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");
                                cse4589_print_and_log("%s\n", server_payload);
                                cse4589_print_and_log("[%s:END]\n", "RECEIVED");
                            }

                            if(strncmp("ms", buf, 2) == 0) {
                                char *ip = strtok(server_payload, " ");
                                char *msg = strtok(NULL, "");
                                // printf("pay: %s\nip: %s\nmsg:%s\n", buf, ip, msg);
                                cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");
                                cse4589_print_and_log("msg from:%s\n[msg]:%s\n", ip, msg);
                                cse4589_print_and_log("[%s:END]\n", "RECEIVED");

                                char *ak = "ak";
                                if(send(server_fd, ak, sizeof(ak),0) == -1) {
                                    perror("send");
                                }
                                // printf("sent %s\n", ak);
                            } else if(strncmp("bs", buf, 2) == 0) {
                                if(strcmp(server_payload, "fail") == 0) {
                                    cse4589_print_and_log("[%s:ERROR]\n", "BLOCK");
                                    cse4589_print_and_log("[%s:END]\n", "BLOCK");
                                } else {
                                    cse4589_print_and_log("[%s:SUCCESS]\n", "BLOCK");
                                    cse4589_print_and_log("[%s:END]\n", "BLOCK");

                                }
                            } else if(strncmp("us", buf, 2) == 0) {
                                if(strcmp(server_payload, "fail") == 0) {
                                    cse4589_print_and_log("[%s:ERROR]\n", "UNBLOCK");
                                    cse4589_print_and_log("[%s:END]\n", "UNBLOCK");
                                } else {
                                    cse4589_print_and_log("[%s:SUCCESS]\n", "UNBLOCK");
                                    cse4589_print_and_log("[%s:END]\n", "UNBLOCK");

                                }
                            }
                        }

                    }
                }
            }
        }

    }
    
    close(fd);  
    return 0;
}
