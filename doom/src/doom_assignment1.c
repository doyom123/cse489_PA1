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


    if(strcmp(argv[1], "s") == 0) {
        // List of clients
        Vector clients;
        vec_init(&clients);

        // List of messages
        VectorStr msgs;
        vecstr_init(&msgs);

        if(listen(fd, BACKLOG) != 0) {
            perror("listen");
            exit(EXIT_FAILURE);
        } 
        
        char msg[256];
        char buf[BUFSIZE];
        int nbytes, new_fd;
        struct sockaddr_in remoteaddr;
        socklen_t addrlen;

        FD_SET(0, &master);
        FD_SET(fd, &master);
        // Listing listing;
        for(;;) {
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
                            cse4589_print_and_log("AUTHOR:%s\n", msg);
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
                            vec_print_list(&clients);
                            // for(int i = 0; i < clients.size; i++) {
                            //     printf("%d %s %s %s", i+1, clients.data[i].hostname, clients.data[i].address, clients.data[i].port);
                            // }


                        } else if(strcmp(token, "STATISTICS") == 0) {
                            vec_print_statistic(&clients);
                        } else if(strcmp(token, "BLOCKED") == 0) {
                            char *client_ip = strtok(NULL, "");
                            vec_print_blocked(&clients, client_ip);
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
                            printf("selectserver: new connection fd: %d\n", new_fd);
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
                            char client_payload[BUFSIZE];
                            // Check command received from client == BROADCAST
                            // printf("**payload: %s\n", client_payload);
                            strncpy(client_payload, &(buf[2]), nbytes-2);
                            // printf("buf before: %s\n", buf);
                            // printf("payload before: %s\n", client_payload);


                            // BROADCAST
                            if(strncmp("br", buf, 2) == 0) {
                                // printf("brconfirmed\n");
                                for(int j = 1; j <= fd_max; j++) {
                                    if(FD_ISSET(j, &master)) {
                                        if(j != fd) {
                                            if(send(j, client_payload, nbytes-2, 0) == -1) {
                                                perror("send");
                                            }
                                            // printf("sent %d bytes to fd=%d: %s\n", nbytes-2, j, client_payload);
                                            
                                        } 
                                    }
                                }
                            }
                            // Check command received from client == SEND
                            // #TODO: NOT SENDING
                            if(strncmp("se", buf, 2) == 0) {
                                char *client_ip = strtok(payload, " ");
                                char *message = strtok(NULL, "");
                                int len = strlen(message);                                
                                // printf("ip: %s\nmessage: %s\n", client_ip, message);
                                int recvr_fd = vec_get_fd(&clients, client_ip);
                                printf("recvr_fd: %d", recvr_fd);
                                if(recvr_fd >= 0) {
                                    if(send(recvr_fd, message, strlen(message), 0) == -1) {
                                        perror("send");
                                    }
                                    // printf("sent %d bytes to fd=%d: %s\n", len, recvr_fd, message); 
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

                                int result = vec_insert_sorted(&clients, listing);

                                // Send client list
                                char c_payload[1024];
                                char head[3] = "li";
                                char client_list[1024] = "";
                                vec_clients(&clients, client_list);
                                snprintf(c_payload, sizeof(c_payload),"%s %s", head, client_list);
                                if(send(new_fd, c_payload, strlen(c_payload), 0) == -1) {
                                    perror("send");
                                }

                                if(result == 1) {
                                    // #TODO: send all buffered msgs to client
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
                                char *head = "li";
                                char client_list[1024] = "";
                                char payload[1024] = "";
                                vec_clients(&clients, client_list);
                                snprintf(payload, sizeof(payload), "%s %s", head, client_list);
                                if(send(client_fd, payload, strlen(payload), 0) == -1) {
                                    perror("send");
                                }
                                printf("payload:\n%s\n", payload);
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

                                vec_block(&clients, client_ip, block_ip);
                                vec_print_blocked(&clients, client_ip);

                            }

                            if(strncmp("ub", buf, 2) == 0) {
                                // printf("ub: %s\n", client_payload);
                                char *client_ip = strtok(client_payload, " ");
                                char *unblock_ip = strtok(NULL, "");

                                vec_unblock(&clients, client_ip, unblock_ip);
                                vec_print_blocked(&clients, client_ip);
                            }

                        }

                    }
                }

            }
        }   // end for
        vec_free(&clients);
        vecstr_free(&msgs);

    }



    // Client Code
    else {
        char clients[1024];
        bool logged_in = false;

        if(listen(fd, BACKLOG) != 0) {
            perror("listen");
            exit(EXIT_FAILURE);
        } 

        char msg[256];
        char buf[BUFSIZE];
        int nbytes, new_fd;
        struct sockaddr_storage remoteaddr;
        socklen_t addrlen;
        int server_fd = -1;

        FD_SET(0, &master);
        FD_SET(fd, &master);

        for(;;) {
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
                            cse4589_print_and_log("AUTHOR:%s\n", msg);
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
                            printf("LIST: \n%s", clients);
                        }

                        if(strcmp(token, "LOGIN") == 0 && logged_in == false) {
                            // LOGIN <server-ip> <server-port>
                            // #TODO CHANGE THIS TO WORK FOR IPV6 AS WELL
                            char *server_ip  = strtok(NULL, " ");
                            char *server_port = strtok(NULL, " ");
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
                            	perror("LOGIN connect");
                            }


                            FD_SET(server_fd, &master);
                            if(server_fd > fd_max) fd_max = server_fd;
                            printf("selectserver: new connection fd: %d\n", server_fd);

                            // Send server client listening port
                            char *head = "lo";
                            char port_str[32];
                            memset(port_str, '\0', sizeof(port_str));
                            snprintf(port_str, sizeof(port_str), "%s%d", head, port_int);
                            printf("sending port info: %s\n", port_str);
                            if(send(server_fd, port_str, strlen(port_str), 0) == -1) {
                                perror("send");
                            }

                            logged_in = true;


                        } else if(strcmp(token, "REFRESH") == 0) {
                            // REFRESH
                            char payload[256];
                            char *head = "re";
                            snprintf(payload, sizeof(payload), "%s%s", head, ip_addr);
                            if(send(server_fd, payload, strlen(payload), 0) == -1) {
                                perror("send");
                            }
                            printf("sent: %s\n", payload);

                        } else if(strcmp(token, "SEND") == 0) {
                            // SEND <client-ip> <msg>
                            // char *client_ip = strtok(NULL, " ");
                            // char *msg = strtok(NULL, " ");
                            char payload[256];
                            char *head = "se";
                            char *message = strtok(NULL, "");
                            snprintf(payload, sizeof(payload), "%s%s", head, message);
                            int len = strlen(payload);
                            if(server_fd != -1) {
                                // Send to server
                                if(send(server_fd, payload, len+1, 0) == -1) {
                                    perror("send");
                                }
                            }

                        } else if(strcmp(token, "BROADCAST") == 0) {
                            // BROADCAST <msg>
                            char payload[256];
                            char *head = "br";
                            char *message = strtok(NULL, "");
                            snprintf(payload, sizeof(payload), "%s%s", head, message);
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
                            snprintf(payload, sizeof(payload), "%s%s %s", head, ip_addr, client_ip);
                            if(send(server_fd, payload, strlen(payload), 0) == -1) {
                                perror("send");
                            }
                            printf("block: %s\n", payload);

                        } else if(strcmp(token, "UNBLOCK") == 0) {
                            // UNBLOCK <client-ip>
                            char *client_ip = strtok(NULL, " ");
                            char payload[256] = "";
                            char *head = "ub";
                            snprintf(payload, sizeof(payload), "%s%s %s", head, ip_addr, client_ip);
                            if(send(server_fd, payload, strlen(payload), 0) == -1) {
                                perror("send");
                            }
                            printf("unblock: %s\n", payload);


                        } else if(strcmp(token, "LOGOUT") == 0) {
                            // LOGOUT
                            char payload[256];
                            char *head = "lg";
                            snprintf(payload, sizeof(payload), "%s%s", head, ip_addr);
                            if(send(server_fd, payload, strlen(payload), 0) == -1) {
                                perror("send");
                            }

                            if(close(server_fd) == -1) {
                                perror("close");
                            }
                            printf("cleared server_fd %d\n", server_fd);
                            FD_CLR(server_fd, &master);
                            // server_fd = -1;

                            logged_in = false;

                        } else if(strcmp(token, "EXIT") == 0) {
                            // EXIT
                            // TODO: send signal to server
                            char payload[256];
                            char *head = "ex";
                            snprintf(payload, sizeof(payload), "%s%s", head, ip_addr);
                            if(send(server_fd, payload, sizeof(payload), 0) == -1) {
                                perror("send");
                            }
                            exit(0);
                        } else if(strcmp(token, "SENDFILE") == 0) {
                            // SENDFILE <client-ip> <file>
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
                            printf("cleared %d", i);
                            close(i);
                            FD_CLR(i, &master);
                        } else {
                            int len = strlen(buf);
                            printf("recvd %d bytes: %s\n", nbytes, buf);

                            char *head = strtok(buf, " ");
                            char *message = strtok(NULL, "");
                            printf("head: %s\n", head);
                            // Received list of clients
                            if(strcmp(head, "li") == 0) {
                                printf("message: %s\n", message);
                                memset(clients, '\0', sizeof(clients));
                                strncpy(clients, message, strlen(message));
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