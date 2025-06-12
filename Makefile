NAME := ft_nmap
CC := clang
CPPFLAGS := -Iincludes
CFLAGS := -Wall -Wextra -Werror
LDLIBS := -lpcap
SRCS := main.c send_packet.c routines.c utils.c print_analyse.c parser.c
OBJS := $(SRCS:.c=.o)
DEPS := $(SRCS:.c=.d)
OBJDIR := obj
DEPDIR := dep
SUFFIXES += .d

vpath %.c srcs
vpath %.o $(OBJDIR)
vpath %.d $(DEPDIR)

all: $(NAME)

$(NAME): $(DEPS) $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(addprefix $(OBJDIR)/, $(OBJS)) $(LDLIBS)

%.o: %.c $(DEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $(OBJDIR)/$@

%.d: %.c
	$(CC) $(CPPFLAGS) -MM -MF $(DEPDIR)/$@ $<

ifneq "$(MAKECMDGOALS)" "clean"
 -include $(addprefix $(DEPDIR)/, $(DEPS))
endif

debug: CFLAGS += -g -DDEBUG=1
debug: $(NAME)

$(OBJS): | $(OBJDIR)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(DEPS): | $(DEPDIR)

$(DEPDIR):
	mkdir -p $(DEPDIR)

clean:
	rm -rf $(OBJDIR) $(DEPDIR)

fclean: clean
	$(RM) -rf $(NAME)

re: fclean all

.PHONY: all debug clean fclean re
