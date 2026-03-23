NAME=			stockholm

CXX=			g++

CXXFLAGS= 		-Wall -Wextra -Werror -g3 -std=c++20 -MMD

INCLD=  		-I ./include/

SRC_PATH= 		src/
OBJ_PATH= 		obj/

SRC=			$(SRC_PATH)main.cpp			\
				$(SRC_PATH)Stockholm.cpp	\
				
OBJ= 			$(addprefix $(OBJ_PATH), $(notdir $(SRC:.cpp=.o)))

all: $(NAME)

-include $(OBJ:.o=.d)

$(OBJ_PATH):
	@mkdir $(OBJ_PATH)

$(OBJ_PATH)%.o: $(SRC_PATH)%.cpp | $(OBJ_PATH)
	@$(CXX) $(CXXFLAGS) $(INCLD) -c $< -o $@

$(NAME): $(OBJ)
	@$(CXX) $(OBJ) -o $(NAME) -lsodium

clean:
	@rm -rf $(OBJ_PATH)

fclean: clean
	@rm -rf $(NAME)

re: fclean all

.PHONY: all clean fclean re
