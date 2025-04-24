SRCS		= srcs/main.c			\
			  srcs/send_packet.c	\
			  srcs/packet_info.c	\
			  srcs/routines.c		\
			  srcs/utils.c			\
			  srcs/print_analyse.c

OBJS		= ${SRCS:.c=.o} 

NAME		= ft_nmap

INCLUDES	= -I includes

CC			= clang

CCFLAGS	= -Wall -Werror -Wextra

PCAPFLAGS = -lpcap

%.o: %.c 
		$(CC) $(CCFLAGS) $(INCLUDES) -c $< -o $@

all:		${NAME}

${NAME}:	$(OBJS)
			$(CC) $(CCFLAGS) $(PCAPFLAGS) $(OBJS) $(LIB) -o $(NAME)

clean:	
					rm -f ${OBJS}

fclean:		clean
					rm -f ${NAME}

re:			fclean all

.PHONY:		all clean fclean re