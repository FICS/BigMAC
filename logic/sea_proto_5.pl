% SEAndroid Prolog Engine (Attach Graph)
% Protoype #5
% Jan 16, 2019
% daveti
%
% NOTE: this is NOT DAG, since there is a cycle
% enabled by bidirectional edges between (n3, n5)
% and (n5, n8)
%
% Query(n1, n5)
% Query(n1, n8)
%
% n1->n2->n3->n6->n7->n8
%     |   A       A
%     v   v       |
%     n4->n5<------

% Edge(start_node, end_node)
edge(n1, n2).
edge(n2, n3).
edge(n2, n4).
edge(n4, n5).
edge(n3, n5).
edge(n3, n6).
edge(n6, n7).
edge(n5, n7).
edge(n7, n8).
edge(n7, n5).
edge(n5, n3).

% Connected(start_node, end_node)
% return true if two nodes are connected
connected(S, S).
connected(S, E) :-
	edge(S, N),
	connected(N, E).
	
% Path(start_node, end_node, path)
% return true if path is a path from S to E
path(S, S, [S]).
path(S, E, [S|P]) :-
	edge(S, N),
	path(N, E, P).

% Query(start_node, end_node)
% return all viable paths between S and E
% NOTE: query could NOT handle loop
query(S, E, Z) :-
	findall(X, path(S, E, X), Z).


% https://www.cpp.edu/~jrfisher/www/prolog_tutorial/2_15.html
connected2(X,Y) :-
	edge(X,Y);
	edge(Y,X).

travel(A,B,P,[B|P]) :- 
	edge(A,B).
travel(A,B,Visited,Path) :-
	edge(A,C),           
	C \== B,
	\+member(C,Visited),
	travel(C,B,[C|Visited],Path).

path2(A,B,Path) :-
	travel(A,B,[A],Q), 
	reverse(Q,Path).

query2(A,B,Z) :-
	findall(X, path2(A,B,X), Z).


