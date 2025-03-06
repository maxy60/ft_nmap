SRCS		= srcs/main.c

OBJS		= ${SRCS:.c=.o} 

NAME		= ft_nmap

INCLUDES	= -I includes

CC			= clang

CCFLAGS	= -Wall -Werror -Wextra

%.o: %.c 
		$(CC) $(CCFLAGS) $(INCLUDES) -c $< -o $@

all:		${NAME}

${NAME}:	$(OBJS)
			$(CC) $(CCFLAGS) $(OBJS) $(LIB) -o $(NAME)

clean:	
					rm -f ${OBJS}

fclean:		clean
					rm -f ${NAME}

re:			fclean all

.PHONY:		all clean fclean re